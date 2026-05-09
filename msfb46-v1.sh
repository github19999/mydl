#!/bin/bash

#===============================================================
#  服务器安全配置一键部署脚本 v2.2
#  支持: SSH密钥登录 / BBR加速 / fail2ban / IPv4/IPv6控制
#  兼容: apt/yum/dnf/pacman/apk/zypper
#  修复: CRLF问题 / SSH配置重复追加 / fail2ban日志路径兼容
#===============================================================

#===============================================================
# 颜色定义
#===============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()    { echo -e "${BLUE}[STEP]${NC} $1"; }
log_success() { echo -e "${CYAN}[OK]${NC} $1"; }

#===============================================================
# 全局变量
#===============================================================
SSH_PORT=""
PUBLIC_KEY=""
IP_PRIORITY="none"
IP_DISABLE="none"
SSHD_CONFIG="/etc/ssh/sshd_config"
SYSCTL_CONF="/etc/sysctl.conf"
FAIL2BAN_INSTALLED=0
INIT_SYSTEM="unknown"
PKG_MANAGER="unknown"
OS_ID="unknown"
OS_NAME="Unknown"

#===============================================================
# 通用函数库
#===============================================================

# 清理行尾 \r 字符（修复 Windows 换行符导致的 Bad configuration option）
strip_cr() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    sed -i 's/\r$//' "$file"
}

# 安全追加配置行（防重复追加、防 CRLF）
safe_append() {
    local file="$1"
    local line="$2"
    line=$(echo "$line" | sed 's/\r$//')
    grep -qF -- "$line" "$file" 2>/dev/null && return 1
    echo "$line" >> "$file"
    return 0
}

# 安全替换/新增配置项（兼容注释/非注释/多空格格式）
safe_replace() {
    local file="$1"
    local key="$2"
    local value="$3"
    value=$(echo "$value" | sed 's/\r$//')

    # 匹配 key 可能有空格的前缀
    if grep -qE "^\s*${key}\s+" "$file" 2>/dev/null; then
        sed -i -E "s|^\s*${key}\s+.*|${value}|" "$file"
        return 0
    fi
    if grep -qE "^\s*#\s*${key}\s+" "$file" 2>/dev/null; then
        sed -i -E "s|^\s*#\s*${key}\s.*|${value}|" "$file"
        return 0
    fi
    echo "$value" >> "$file"
    return 0
}

# 注释掉指定配置行
comment_line() {
    local file="$1"
    local pattern="$2"
    sed -i "s|^\s*${pattern}|#${pattern}|" "$file"
}

#===============================================================
# 环境检测
#===============================================================

detect_init_system() {
    if [[ -d /run/systemd/system ]]; then
        INIT_SYSTEM="systemd"
    elif [[ -f /sbin/init ]] && /sbin/init --version 2>/dev/null | grep -q upstart; then
        INIT_SYSTEM="upstart"
    elif [[ -f /etc/init.d/sshd ]] || [[ -f /etc/init.d/ssh ]]; then
        INIT_SYSTEM="sysvinit"
    elif [[ -d /etc/runlevels ]]; then
        INIT_SYSTEM="OpenRC"
    else
        INIT_SYSTEM="unknown"
    fi
    log_info "初始化系统: $INIT_SYSTEM"
}

detect_os_and_pkg_manager() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_NAME="$NAME"
        OS_VERSION="$VERSION_ID"
    else
        OS_ID="unknown"
        OS_NAME="Unknown"
        OS_VERSION=""
    fi
    log_info "操作系统: $OS_NAME ($OS_VERSION)"

    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt-get"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
    elif command -v apk &>/dev/null; then
        PKG_MANAGER="apk"
    elif command -v zypper &>/dev/null; then
        PKG_MANAGER="zypper"
    else
        PKG_MANAGER="unknown"
    fi
    log_info "包管理器: $PKG_MANAGER"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

#===============================================================
# 服务管理（兼容 systemd / sysvinit / OpenRC）
#===============================================================

get_ssh_service_name() {
    for svc in sshd ssh; do
        systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1 && { echo "$svc"; return; }
        [[ -f "/etc/init.d/$svc" ]] && { echo "$svc"; return; }
    done
    echo "sshd"
}

service_enable() {
    local svc="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl enable "$svc" 2>/dev/null
            ;;
        sysvinit|OpenRC)
            command -v update-rc.d &>/dev/null && update-rc.d "$svc" defaults 2>/dev/null
            command -v rc-update  &>/dev/null && rc-update add "$svc" default 2>/dev/null
            ;;
    esac
}

service_restart() {
    local svc="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl restart "$svc" 2>&1
            ;;
        sysvinit|OpenRC)
            [[ -f "/etc/init.d/$svc" ]] && "/etc/init.d/$svc" restart 2>&1
            command -v service &>/dev/null && service "$svc" restart 2>&1
            ;;
    esac
}

service_start() {
    local svc="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl start "$svc" 2>&1
            ;;
        sysvinit|OpenRC)
            [[ -f "/etc/init.d/$svc" ]] && "/etc/init.d/$svc" start 2>&1
            ;;
    esac
}

service_status() {
    local svc="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl is-active "$svc" &>/dev/null && return 0 || return 1
            ;;
        sysvinit|OpenRC)
            [[ -f "/etc/init.d/$svc" ]] && "/etc/init.d/$svc" status &>/dev/null && return 0 || return 1
            ;;
    esac
    return 1
}

#===============================================================
# 用户输入
#===============================================================

get_public_key() {
    echo ""
    log_step "配置SSH密钥登录"
    echo "请输入你的SSH公钥 (ssh-rsa / ssh-ed25519 / ecdsa-sha2 开头):"
    echo "提示: 粘贴后按回车即可"
    echo ""
    read -r PUBLIC_KEY

    if [[ -z "$PUBLIC_KEY" ]]; then
        log_error "公钥不能为空"
        exit 1
    fi

    # 清理 \r 和多余空白，统一成单行
    PUBLIC_KEY=$(echo "$PUBLIC_KEY" | sed 's/\r//' | tr -s '[:space:]' ' ' | sed 's/[[:space:]]*$//')

    if [[ ! "$PUBLIC_KEY" =~ ^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2-nistp|sk-ssh) ]]; then
        log_warn "公钥格式可能不正确，但继续执行..."
        echo "内容预览: ${PUBLIC_KEY:0:60}..."
    fi
}

get_ssh_port() {
    echo ""
    log_step "配置SSH端口"
    echo "请输入新的SSH端口 (1024-65535，建议10000+，默认43916):"
    read -r SSH_PORT

    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT=43916
    fi

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
        log_error "端口必须是数字"
        exit 1
    fi

    if [[ $SSH_PORT -lt 1024 || $SSH_PORT -gt 65535 ]]; then
        log_error "端口范围应在 1024-65535 之间"
        exit 1
    fi

    # 检查端口占用
    if command -v ss &>/dev/null && ss -tlnp 2>/dev/null | grep -q ":$SSH_PORT "; then
        log_warn "端口 $SSH_PORT 已被占用，继续执行..."
    elif command -v netstat &>/dev/null && netstat -tlnp 2>/dev/null | grep -q ":$SSH_PORT "; then
        log_warn "端口 $SSH_PORT 已被占用，继续执行..."
    fi

    log_info "将使用SSH端口: $SSH_PORT"
}

get_ip_priority() {
    echo ""
    log_step "配置IP协议优先级"
    echo "1) IPv4优先"
    echo "2) IPv6优先"
    echo "3) 保持不变"
    echo -n "请输入选择 (1-3，默认1): "
    read -r choice
    [[ -z "$choice" ]] && choice=1

    case $choice in
        1) IP_PRIORITY="ipv4"; log_info "将设置IPv4优先" ;;
        2) IP_PRIORITY="ipv6"; log_info "将设置IPv6优先" ;;
        3) IP_PRIORITY="none"; log_info "将保持IP协议优先级不变" ;;
        *) IP_PRIORITY="ipv4"; log_warn "无效选择，使用默认 IPv4优先" ;;
    esac
}

get_ip_disable() {
    echo ""
    log_step "配置IP协议禁用"
    echo "1) 禁用IPv6"
    echo "2) 禁用IPv4"
    echo "3) 保持不变"
    echo -n "请输入选择 (1-3，默认1): "
    read -r choice
    [[ -z "$choice" ]] && choice=1

    case $choice in
        1) IP_DISABLE="ipv6"; log_info "将禁用IPv6" ;;
        2) IP_DISABLE="ipv4"; log_info "将禁用IPv4" ;;
        3) IP_DISABLE="none"; log_info "将保持IP协议状态不变" ;;
        *) IP_DISABLE="ipv6"; log_warn "无效选择，使用默认禁用IPv6" ;;
    esac
}

#===============================================================
# 安装基础软件（支持多包管理器）
#===============================================================

install_basics() {
    log_step "更新系统并安装基础软件"

    case $PKG_MANAGER in
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt update -y 2>&1 | tail -3
            apt install -y --no-install-recommends \
                curl sudo wget git unzip nano vim \
                fail2ban python3 python3-pip ufw 2>&1 | tail -5
            ;;
        yum)
            yum install -y epel-release 2>/dev/null || true
            yum install -y curl sudo wget git unzip nano vim \
                fail2ban python3 firewalld 2>&1 | tail -5
            ;;
        dnf)
            dnf install -y epel-release 2>/dev/null || true
            dnf install -y curl sudo wget git unzip nano vim \
                fail2ban python3 firewalld 2>&1 | tail -5
            ;;
        pacman)
            pacman -Sy --noconfirm curl sudo wget git unzip nano vim \
                fail2ban python3 iptables 2>&1 | tail -5
            ;;
        apk)
            apk add curl sudo wget git unzip nano vim \
                fail2ban python3 iptables 2>&1 | tail -5
            ;;
        zypper)
            zypper install -y curl sudo wget git unzip nano vim \
                fail2ban python3 iptables 2>&1 | tail -5
            ;;
        *)
            log_error "不支持的包管理器: $PKG_MANAGER"
            exit 1
            ;;
    esac

    [[ $? -eq 0 ]] && log_success "基础软件安装完成" \
        || log_warn "部分软件安装可能失败，继续执行..."
}

#===============================================================
# 检查/修复 fail2ban 安装状态
#===============================================================

fix_fail2ban_deps() {
    log_step "检查 fail2ban 安装状态"

    if command -v fail2ban-client &>/dev/null; then
        FAIL2BAN_INSTALLED=1
        log_success "fail2ban 已安装"
        return 0
    fi

    log_warn "fail2ban 未安装，尝试修复..."

    # 安装 Python（fail2ban 依赖）
    case $PKG_MANAGER in
        apt-get)
            apt install -y python3 python3-pip 2>&1 | tail -3
            ;;
        yum)
            yum install -y python3 python3-pip 2>&1 | tail -3
            ;;
        dnf)
            dnf install -y python3 python3-pip 2>&1 | tail -3
            ;;
        pacman)
            pacman -Sy --noconfirm python python-pip 2>&1 | tail -3
            ;;
        apk)
            apk add python3 py3-pip 2>&1 | tail -3
            ;;
    esac

    # 通过 pip 兜底安装
    local pip_bin
    pip_bin=$(command -v pip3 || command -v pip 2>/dev/null)
    if [[ -n "$pip_bin" ]]; then
        $pip_bin install fail2ban 2>&1 | tail -5
        [[ $? -eq 0 ]] && FAIL2BAN_INSTALLED=1 && log_success "fail2ban 通过 pip 安装成功" && return 0
    fi

    log_error "fail2ban 安装失败，将跳过"
    return 1
}

#===============================================================
# 启用BBR拥塞控制算法
#===============================================================

enable_bbr() {
    log_step "启用BBR拥塞控制算法"

    local current=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    local current_qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')

    if [[ "$current" == "bbr" ]] && [[ "$current_qdisc" == "fq" ]]; then
        log_info "BBR已启用 (qdisc=$current_qdisc, congestion=$current)"
        return
    fi

    # 避免重复写入
    grep -q "net.core.default_qdisc=fq" "$SYSCTL_CONF" 2>/dev/null || \
        echo "net.core.default_qdisc=fq" >> "$SYSCTL_CONF"
    grep -q "net.ipv4.tcp_congestion_control=bbr" "$SYSCTL_CONF" 2>/dev/null || \
        echo "net.ipv4.tcp_congestion_control=bbr" >> "$SYSCTL_CONF"

    # 尝试加载 BBR 模块
    modprobe tcp_bbr 2>/dev/null || true

    sysctl -p >/dev/null 2>&1

    local new=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$new" == "bbr" ]]; then
        log_success "BBR启用成功"
    else
        log_warn "BBR需要更高内核版本 (当前: $(uname -r))，配置已写入重启后生效"
    fi
}

#===============================================================
# 设置IP协议优先级
#===============================================================

set_ip_priority() {
    [[ "$IP_PRIORITY" == "none" ]] && return

    log_step "设置IP协议优先级"

    local GAI_CONF="/etc/gai.conf"
    [[ ! -f "$GAI_CONF" ]] && {
        log_warn "/etc/gai.conf 不存在，跳过优先级设置"
        return
    }

    strip_cr "$GAI_CONF"
    cp "$GAI_CONF" "${GAI_CONF}.backup.$(date +%Y%m%d_%H%M%S)"

    if [[ "$IP_PRIORITY" == "ipv4" ]]; then
        if grep -q "^#precedence ::ffff:0:0/96" "$GAI_CONF"; then
            sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' "$GAI_CONF"
        elif ! grep -q "^precedence ::ffff:0:0/96" "$GAI_CONF"; then
            echo "precedence ::ffff:0:0/96  100" >> "$GAI_CONF"
        fi
        log_success "IPv4优先已设置"
    elif [[ "$IP_PRIORITY" == "ipv6" ]]; then
        if grep -q "^precedence ::ffff:0:0/96" "$GAI_CONF"; then
            sed -i 's/^precedence ::ffff:0:0\/96  100/#precedence ::ffff:0:0\/96  100/' "$GAI_CONF"
        fi
        log_success "IPv6优先已设置"
    fi
}

#===============================================================
# 禁用指定IP协议
#===============================================================

disable_ip_protocol() {
    [[ "$IP_DISABLE" == "none" ]] && return

    log_step "禁用IP协议"
    strip_cr "$SYSCTL_CONF"
    cp "$SYSCTL_CONF" "${SYSCTL_CONF}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

    if [[ "$IP_DISABLE" == "ipv6" ]]; then
        if grep -q "net.ipv6.conf.all.disable_ipv6=1" "$SYSCTL_CONF"; then
            log_info "IPv6禁用配置已存在"
            return
        fi
        cat >> "$SYSCTL_CONF" << 'EOF'

# IPv6 disabled by script
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
        sysctl -p >/dev/null 2>&1
        [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null) == "1" ]] \
            && log_success "IPv6已禁用" \
            || log_warn "IPv6禁用可能需要重启后生效"

    elif [[ "$IP_DISABLE" == "ipv4" ]]; then
        log_warn "禁用IPv4是危险操作，可能导致系统无法访问！"
        echo -n "确定要禁用IPv4吗？(y/N): "
        read -r confirm
        if [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]]; then
            log_info "已取消IPv4禁用"
            IP_DISABLE="none"
            return
        fi
        if ! grep -q "net.ipv4.conf.all.disable_ipv4=1" "$SYSCTL_CONF"; then
            cat >> "$SYSCTL_CONF" << 'EOF'

# IPv4 disabled by script
net.ipv4.conf.all.disable_ipv4=1
net.ipv4.conf.default.disable_ipv4=1
EOF
        fi
        log_warn "IPv4禁用配置已添加，重启后生效"
    fi
}

#===============================================================
# 配置SSH密钥登录
#===============================================================

setup_ssh_key() {
    log_step "配置SSH密钥登录"

    # 清理公钥中的 \r
    PUBLIC_KEY=$(echo "$PUBLIC_KEY" | sed 's/\r//')

    # 自动检测目标用户目录
    local target_user="root"
    local target_home="/root"
    local cur_home

    if [[ $EUID -eq 0 ]]; then
        cur_home=$(getent passwd "$(whoami)" | cut -d: -f6)
        if [[ -n "$cur_home" ]] && [[ "$cur_home" != "/root" ]]; then
            log_info "检测到用户目录: $cur_home"
            target_user=$(whoami)
            target_home="$cur_home"
        fi
    fi

    log_info "目标用户: $target_user ($target_home)"

    # 创建目录并设置严格权限
    mkdir -p "$target_home/.ssh"
    chmod 700 "$target_home/.ssh"

    # 追加公钥（保留已有密钥）
    if ! grep -Fq "$PUBLIC_KEY" "$target_home/.ssh/authorized_keys" 2>/dev/null; then
        echo "$PUBLIC_KEY" >> "$target_home/.ssh/authorized_keys"
        log_info "公钥已添加"
    else
        log_info "公钥已存在，跳过"
    fi

    chmod 600 "$target_home/.ssh/authorized_keys"
    chown -R "$target_user:$target_user" "$target_home/.ssh"

    log_success "SSH密钥配置完成"
}

#===============================================================
# 配置SSH安全设置（关键修复）
#===============================================================

configure_ssh() {
    log_step "配置SSH安全设置"

    local SSH_SVC
    SSH_SVC=$(get_ssh_service_name)
    log_info "SSH服务名: $SSH_SVC"

    # 备份原配置
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
    # 关键修复：写入前清除 \r，防止 Bad configuration option
    strip_cr "$SSHD_CONFIG"

    # ---- 1. 显式开启密钥认证 ----
    safe_replace "$SSHD_CONFIG" "PubkeyAuthentication" "PubkeyAuthentication yes"

    # ---- 2. 设置密钥文件路径 ----
    safe_replace "$SSHD_CONFIG" "AuthorizedKeysFile" "AuthorizedKeysFile .ssh/authorized_keys"

    # ---- 3. 允许root密钥登录，禁止密码登录 ----
    safe_replace "$SSHD_CONFIG" "PermitRootLogin" "PermitRootLogin prohibit-password"

    # ---- 4. 禁用密码认证 ----
    safe_replace "$SSHD_CONFIG" "PasswordAuthentication" "PasswordAuthentication no"

    # ---- 5. 禁用空密码登录 ----
    safe_replace "$SSHD_CONFIG" "PermitEmptyPasswords" "PermitEmptyPasswords no"

    # ---- 6. 禁用ChallengeResponse认证 ----
    safe_replace "$SSHD_CONFIG" "ChallengeResponseAuthentication" "ChallengeResponseAuthentication no"

    # ---- 7. 禁用GSSAPI认证（减少认证开销） ----
    safe_replace "$SSHD_CONFIG" "GSSAPIAuthentication" "GSSAPIAuthentication no"

    # ---- 8. 禁用X11转发 ----
    safe_replace "$SSHD_CONFIG" "X11Forwarding" "X11Forwarding no"

    # ---- 9. 禁用Agent转发 ----
    safe_replace "$SSHD_CONFIG" "AllowAgentForwarding" "AllowAgentForwarding no"

    # ---- 10. 禁用TCP转发 ----
    safe_replace "$SSHD_CONFIG" "DisableForwarding" "DisableForwarding no"

    # ---- 11. 修改SSH端口 ----
    # 注释掉原 Port 22（兼容多种写法）
    sed -i -E 's/^(\s*)Port(\s+)22(\s*$)/\1#Port\2 22\3/' "$SSHD_CONFIG" 2>/dev/null
    sed -i -E 's/^Port\s+22(\s*#.*)*$/Port 43916/' "$SSHD_CONFIG" 2>/dev/null

    # 检查新端口是否已存在
    if ! grep -qE "^Port\s+$SSH_PORT\s*(#.*)*$" "$SSHD_CONFIG"; then
        # 检查 Port 43916 是否存在（被替换后的），如果存在则更新
        if grep -qE "^Port\s+43916\s*(#.*)*$" "$SSHD_CONFIG"; then
            sed -i "s/^Port 43916$/Port $SSH_PORT/" "$SSHD_CONFIG"
            log_info "已更新端口为: $SSH_PORT"
        else
            echo "Port $SSH_PORT" >> "$SSHD_CONFIG"
            log_info "已添加端口: $SSH_PORT"
        fi
    else
        log_info "端口 $SSH_PORT 已存在于配置中"
    fi

    # ---- 12. 设置客户端支持的密钥算法（兼容新旧客户端） ----
    if ! grep -qE "^PubkeyAcceptedAlgorithms" "$SSHD_CONFIG"; then
        echo "PubkeyAcceptedAlgorithms ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519" >> "$SSHD_CONFIG"
    fi

    # ---- 13. 限制最大认证尝试次数 ----
    safe_replace "$SSHD_CONFIG" "MaxAuthTries" "MaxAuthTries 3"

    # ---- 14. 禁用用户目录遍历 ----
    safe_replace "$SSHD_CONFIG" "PermitUserEnvironment" "PermitUserEnvironment no"

    # ---- 15. 禁用基于主机的认证 ----
    safe_replace "$SSHD_CONFIG" "HostbasedAuthentication" "HostbasedAuthentication no"

    # ---- 最后再次清理 \r（确保无遗漏） ----
    strip_cr "$SSHD_CONFIG"

    log_success "SSH配置完成 (端口=$SSH_PORT, 密钥登录=启用, 密码登录=禁用)"
}

#===============================================================
# 测试SSH配置
#===============================================================

test_ssh_config() {
    log_step "测试SSH配置"

    # 查找 sshd 二进制
    local sshd_bin=""
    for p in /usr/sbin/sshd /sbin/sshd /etc/sbin/sshd; do
        [[ -x "$p" ]] && sshd_bin="$p" && break
    done
    [[ -z "$sshd_bin" ]] && sshd_bin=$(command -v sshd 2>/dev/null)

    if [[ -z "$sshd_bin" ]]; then
        log_warn "未找到 sshd，跳过配置测试"
        return 0
    fi

    log_info "测试配置: $sshd_bin -t"

    if "$sshd_bin" -t 2>&1; then
        log_success "SSH配置测试通过"
        return 0
    else
        log_error "SSH配置测试失败:"
        "$sshd_bin" -t 2>&1

        # 定位问题行
        local err_output=$("$sshd_bin" -t 2>&1)
        local err_line=$(echo "$err_output" | grep -oP 'line \d+' | head -1)
        if [[ -n "$err_line" ]]; then
            local num=$(echo "$err_line" | grep -oP '\d+')
            log_error "问题在第 $num 行: $(sed -n "${num}p" "$SSHD_CONFIG")"
        fi
        return 1
    fi
}

#===============================================================
# 配置 fail2ban（使用 systemd:// 方案，兼容所有发行版）
#===============================================================

detect_ssh_logpath() {
    # 优先尝试 systemd journal
    if command -v systemctl &>/dev/null && systemctl is-active systemd-journald &>/dev/null 2>&1; then
        echo "systemd://"
        return
    fi

    # 备选：文件路径
    for p in /var/log/auth.log /var/log/secure /var/log/sshd.log; do
        if [[ -f "$p" ]]; then
            echo "$p"
            return
        fi
    done

    # 最终兜底
    echo "systemd://"
}

setup_fail2ban() {
    log_step "配置fail2ban"

    fix_fail2ban_deps || {
        log_warn "fail2ban 安装失败，跳过"
        return 0
    }

    [[ $FAIL2BAN_INSTALLED -eq 0 ]] && {
        log_warn "fail2ban 未安装"
        return 0
    }

    local FAIL2BAN_CONF="/etc/fail2ban/jail.local"
    mkdir -p /etc/fail2ban

    # 自动检测 SSH 日志路径和 backend
    local SSH_LOGPATH BACKEND
    SSH_LOGPATH=$(detect_ssh_logpath)

    if [[ "$SSH_LOGPATH" == "systemd://" ]]; then
        BACKEND="systemd"
        log_info "使用 systemd journal 读取日志 (backend=systemd)"
    else
        BACKEND="auto"
        log_info "SSH 日志路径: $SSH_LOGPATH (backend=auto)"
    fi

    cat > "$FAIL2BAN_CONF" << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = -1
findtime = 300
maxretry = 1
loglevel = INFO

[sshd]
enabled = true
port = $SSH_PORT
logpath = $SSH_LOGPATH
backend = $BACKEND
maxretry = 1
findtime = 300
bantime = -1
ignoreip = 127.0.0.1/8 ::1
EOF

    log_info "fail2ban 配置文件已创建"

    # 查找 fail2ban 服务名
    local fb_svc="fail2ban"
    for svc in fail2ban fail2ban-ssh sshd-fail2ban; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
            fb_svc="$svc"
            break
        fi
        [[ -f "/etc/init.d/$svc" ]] && { fb_svc="$svc"; break; }
    done
    log_info "fail2ban 服务名: $fb_svc"

    service_enable "$fb_svc"
    service_start "$fb_svc"
    sleep 3

    # 详细状态检查
    if command -v fail2ban-client &>/dev/null; then
        if fail2ban-client ping &>/dev/null 2>&1; then
            log_success "fail2ban 服务运行正常"

            # 显示防护状态
            local jail_status
            jail_status=$(fail2ban-client status sshd 2>&1)
            log_info "SSH防护状态:"
            echo "$jail_status" | head -10
        else
            log_warn "fail2ban 启动失败，诊断信息:"
            echo ""
            echo "=== 服务状态 ==="
            systemctl status "$fb_svc" --no-pager -l
            echo ""
            echo "=== 最近日志 ==="
            journalctl -u "$fb_svc" -n 15 --no-pager
            echo ""
            echo "=== 建议修复 ==="
            echo "如果日志中有 'Have not found any log file'，请确保:"
            echo "  1. rsyslog 已安装: apt install -y rsyslog"
            echo "  2. 或使用 systemd backend: backend = systemd"
        fi
    else
        log_warn "fail2ban-client 不可用"
    fi
}

#===============================================================
# 重启SSH服务
#===============================================================

restart_ssh() {
    log_step "重启SSH服务"

    local SSH_SVC
    SSH_SVC=$(get_ssh_service_name)
    log_info "重启服务: $SSH_SVC"

    # 配置测试失败时询问是否强制重启
    test_ssh_config || {
        echo -n "SSH配置测试失败，是否强制重启？(y/N): "
        read -r confirm
        if [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]]; then
            log_error "已取消重启，请检查配置"
            exit 1
        fi
        log_warn "强制继续..."
    }

    service_restart "$SSH_SVC"
    sleep 2

    if service_status "$SSH_SVC"; then
        log_success "SSH服务重启成功"
    else
        log_error "SSH服务可能未正常启动"
        log_info "检查命令: systemctl status $SSH_SVC"
        log_info "日志命令: journalctl -u $SSH_SVC -n 20 --no-pager"
    fi
}

#===============================================================
# 配置总结
#===============================================================

show_summary() {
    echo ""
    echo "================================================"
    log_success "服务器安全配置完成！"
    echo "================================================"
    echo ""
    echo "配置总结："
    echo "  - SSH端口:           $SSH_PORT"
    echo "  - 密码登录:           已禁用"
    echo "  - 密钥登录:           已启用"
    echo "  - BBR加速:            已启用"
    echo "  - 操作系统:           $OS_NAME"
    echo "  - 初始化系统:         $INIT_SYSTEM"
    echo "  - 包管理器:           $PKG_MANAGER"
    echo "  - fail2ban:           $([[ $FAIL2BAN_INSTALLED -eq 1 ]] && echo "已安装" || echo "未安装")"
    echo "  - IP协议优先级:       ${IP_PRIORITY:-保持不变}"
    echo "  - IP协议状态:         ${IP_DISABLE:-保持不变}"
    echo ""
    echo "重要提醒："
    echo "  1. 请务必保存好SSH私钥，切勿泄露"
    echo "  2. 新连接命令: ssh -p $SSH_PORT root@服务器IP"
    echo "  3. 连接失败请通过VNC/控制台登录检查"
    echo "  4. 防火墙未配置，请根据需要手动设置"
    echo "  5. IP协议禁用配置重启后生效"
    echo ""

    if [[ $FAIL2BAN_INSTALLED -eq 1 ]]; then
        echo "fail2ban 状态检查命令:"
        echo "  fail2ban-client status sshd"
        echo "  fail2ban-client ping"
        echo ""
    fi

    log_warn "请现在就测试SSH连接，确保能正常登录后再断开当前连接！"
}

#===============================================================
# 主函数
#===============================================================

main() {
    echo "================================================"
    echo "  服务器安全配置一键部署脚本 v2.2"
    echo "  SSH密钥 / BBR / fail2ban / IPv4/IPv6控制"
    echo "================================================"
    echo ""

    check_root
    detect_init_system
    detect_os_and_pkg_manager

    get_public_key
    get_ssh_port
    get_ip_priority
    get_ip_disable

    echo ""
    log_info "开始执行配置，请稍候..."
    echo ""

    install_basics
    enable_bbr
    set_ip_priority
    disable_ip_protocol
    setup_ssh_key
    configure_ssh
    setup_fail2ban
    restart_ssh

    show_summary
}

main "$@"
