#!/bin/bash

#===============================================================
#  服务器安全配置一键部署脚本 v2.1
#  修复: CRLF行尾问题 / SSH配置重复追加 / fail2ban兼容性
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

#===============================================================
# 清理行尾 \r 字符 (关键修复，防止 Bad configuration option)
#===============================================================
strip_cr() {
    sed -i 's/\r$//' "$1" 2>/dev/null
}

#===============================================================
# 安全追加配置行 (防重复追加，防 CRLF)
#===============================================================
safe_append() {
    local file="$1"
    local line="$2"
    # 先去掉行尾可能的 \r
    line=$(echo "$line" | sed 's/\r$//')
    # 检查是否已存在（去掉首尾空格后比较）
    if grep -qF -- "$line" "$file" 2>/dev/null; then
        return 1  # 已存在
    fi
    echo "$line" >> "$file"
    return 0
}

#===============================================================
# 安全替换配置项 (防 CRLF)
#===============================================================
safe_replace() {
    local file="$1"
    local key="$2"
    local value="$3"

    # 去掉 value 中的 \r
    value=$(echo "$value" | sed 's/\r$//')

    # 如果存在该 key（可能有空格或注释），替换它
    if grep -qE "^\s*${key}\s+" "$file" 2>/dev/null; then
        sed -i -E "s|^\s*${key}\s+.*|${value}|" "$file"
        return 0
    fi
    # 如果存在注释形式 #key，替换为非注释
    if grep -qE "^\s*#\s*${key}\s+" "$file" 2>/dev/null; then
        sed -i -E "s|^\s*#\s*${key}\s.*|${value}|" "$file"
        return 0
    fi
    # 都不存在则追加
    echo "$value" >> "$file"
    return 0
}

#===============================================================
# 检测初始化系统
#===============================================================
detect_init_system() {
    if [[ -d /run/systemd/system ]]; then
        INIT_SYSTEM="systemd"
    elif [[ -f /sbin/init ]] && /sbin/init --version 2>/dev/null | grep -q upstart; then
        INIT_SYSTEM="upstart"
    elif [[ -f /etc/init.d/ssh ]] || [[ -f /etc/init.d/sshd ]]; then
        INIT_SYSTEM="sysvinit"
    elif [[ -d /etc/runlevels ]]; then
        INIT_SYSTEM="OpenRC"
    else
        INIT_SYSTEM="unknown"
    fi
    log_info "初始化系统: $INIT_SYSTEM"
}

#===============================================================
# 检测发行版和包管理器
#===============================================================
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
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
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

#===============================================================
# root 权限检查
#===============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

#===============================================================
# 获取 SSH 服务名
#===============================================================
get_ssh_service_name() {
    if systemctl list-unit-files sshd.service &>/dev/null 2>&1; then
        echo "sshd"
    elif systemctl list-unit-files ssh.service &>/dev/null 2>&1; then
        echo "ssh"
    elif [[ -f /etc/init.d/sshd ]]; then
        echo "sshd"
    elif [[ -f /etc/init.d/ssh ]]; then
        echo "ssh"
    else
        # 扫描
        for svc in sshd ssh; do
            if [[ -f "/etc/init.d/$svc" ]]; then
                echo "$svc"
                return
            fi
        done
        echo "sshd"
    fi
}

#===============================================================
# 通用服务管理
#===============================================================
service_enable() {
    local svc="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl enable "$svc" 2>/dev/null
            log_info "systemd: systemctl enable $svc"
            ;;
        sysvinit|OpenRC)
            if command -v update-rc.d &>/dev/null; then
                update-rc.d "$svc" defaults 2>/dev/null
            fi
            if command -v rc-update &>/dev/null; then
                rc-update add "$svc" default 2>/dev/null
            fi
            ;;
    esac
}

service_restart() {
    local svc="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl restart "$svc" 2>&1 | head -5
            ;;
        sysvinit|OpenRC)
            if [[ -f "/etc/init.d/$svc" ]]; then
                "/etc/init.d/$svc" restart 2>&1 | head -5
            elif command -v service &>/dev/null; then
                service "$svc" restart 2>&1 | head -5
            fi
            ;;
    esac
}

service_start() {
    local svc="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl start "$svc" 2>&1 | head -3
            ;;
        sysvinit|OpenRC)
            if [[ -f "/etc/init.d/$svc" ]]; then
                "/etc/init.d/$svc" start 2>&1 | head -3
            fi
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
            if [[ -f "/etc/init.d/$svc" ]]; then
                "/etc/init.d/$svc" status 2>/dev/null && return 0 || return 1
            fi
            ;;
    esac
    return 1
}

#===============================================================
# 获取公钥
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
    fi
}

#===============================================================
# 获取端口
#===============================================================
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

    log_info "将使用SSH端口: $SSH_PORT"
}

#===============================================================
# IP优先级
#===============================================================
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
        *) IP_PRIORITY="none"; log_info "将保持IP协议优先级不变" ;;
    esac
}

#===============================================================
# IP禁用
#===============================================================
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
        *) IP_DISABLE="none"; log_info "将保持IP协议状态不变" ;;
    esac
}

#===============================================================
# 安装基础软件
#===============================================================
install_basics() {
    log_step "更新系统并安装基础软件"

    case $PKG_MANAGER in
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt update -y 2>&1 | tail -3
            apt install -y --no-install-recommends \
                curl sudo wget git unzip nano vim \
                fail2ban python3 python3-pip ufw iptables 2>&1 | tail -5
            ;;
        yum)
            yum install -y epel-release 2>/dev/null || true
            yum install -y curl sudo wget git unzip nano vim \
                fail2ban python3 iptables 2>&1 | tail -5
            ;;
        dnf)
            dnf install -y epel-release 2>/dev/null || true
            dnf install -y curl sudo wget git unzip nano vim \
                fail2ban python3 iptables 2>&1 | tail -5
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

    [[ $? -eq 0 ]] && log_success "基础软件安装完成" || log_warn "部分软件安装可能失败"
}

#===============================================================
# 检查/修复 fail2ban
#===============================================================
fix_fail2ban_deps() {
    log_step "检查 fail2ban 依赖"

    if command -v fail2ban-client &>/dev/null; then
        FAIL2BAN_INSTALLED=1
        log_success "fail2ban 已安装"
        return 0
    fi

    log_warn "fail2ban 未安装，尝试修复..."

    # 安装 Python (fail2ban 依赖)
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

    # 通过 pip 安装
    local pip_bin=$(command -v pip3 || command -v pip)
    if [[ -n "$pip_bin" ]]; then
        $pip_bin install fail2ban 2>&1 | tail -3
        if [[ $? -eq 0 ]]; then
            FAIL2BAN_INSTALLED=1
            log_success "fail2ban 通过 pip 安装成功"
            return 0
        fi
    fi

    log_error "fail2ban 安装失败"
    return 1
}

#===============================================================
# 启用BBR
#===============================================================
enable_bbr() {
    log_step "启用BBR拥塞控制算法"

    local current=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    local current_qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')

    if [[ "$current" == "bbr" ]] && [[ "$current_qdisc" == "fq" ]]; then
        log_info "BBR已经启用 (qdisc=$current_qdisc, congestion=$current)"
        return
    fi

    # 避免重复写入
    grep -q "net.core.default_qdisc=fq" "$SYSCTL_CONF" 2>/dev/null || \
        echo "net.core.default_qdisc=fq" >> "$SYSCTL_CONF"
    grep -q "net.ipv4.tcp_congestion_control=bbr" "$SYSCTL_CONF" 2>/dev/null || \
        echo "net.ipv4.tcp_congestion_control=bbr" >> "$SYSCTL_CONF"

    sysctl -p >/dev/null 2>&1

    local new=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$new" == "bbr" ]]; then
        log_success "BBR启用成功"
    else
        log_warn "BBR可能需要更高内核版本 (当前: $(uname -r))，配置已写入重启后生效"
    fi
}

#===============================================================
# 设置IP协议优先级
#===============================================================
set_ip_priority() {
    [[ "$IP_PRIORITY" == "none" ]] && return

    log_step "设置IP协议优先级"

    local GAI_CONF="/etc/gai.conf"
    [[ ! -f "$GAI_CONF" ]] && log_warn "/etc/gai.conf 不存在，跳过" && return

    strip_cr "$GAI_CONF"
    cp "$GAI_CONF" "${GAI_CONF}.backup.$(date +%Y%m%d_%H%M%S)"

    if [[ "$IP_PRIORITY" == "ipv4" ]]; then
        if grep -q "^precedence ::ffff:0:0/96" "$GAI_CONF"; then
            sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' "$GAI_CONF"
        elif ! grep -q "^precedence ::ffff:0:0/96" "$GAI_CONF"; then
            echo "precedence ::ffff:0:0/96  100" >> "$GAI_CONF"
        fi
        log_success "IPv4优先已设置"
    elif [[ "$IP_PRIORITY" == "ipv6" ]]; then
        sed -i 's/^precedence ::ffff:0:0\/96  100/#precedence ::ffff:0:0\/96  100/' "$GAI_CONF" 2>/dev/null
        log_success "IPv6优先已设置"
    fi
}

#===============================================================
# 禁用IP协议
#===============================================================
disable_ip_protocol() {
    [[ "$IP_DISABLE" == "none" ]] && return

    log_step "禁用IP协议"
    cp "$SYSCTL_CONF" "${SYSCTL_CONF}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    strip_cr "$SYSCTL_CONF"

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
            && log_success "IPv6已成功禁用" \
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

    # 确定用户目录
    local target_user="root"
    local target_home="/root"

    if [[ $EUID -eq 0 ]]; then
        local cur_home=$(getent passwd "$(whoami)" | cut -d: -f6)
        if [[ -n "$cur_home" ]] && [[ "$cur_home" != "/root" ]]; then
            log_info "检测到用户目录: $cur_home"
            target_user=$(whoami)
            target_home="$cur_home"
        fi
    fi

    log_info "目标用户: $target_user ($target_home)"

    # 创建目录
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
# 配置SSH安全设置 (核心修复)
#===============================================================
configure_ssh() {
    log_step "配置SSH安全设置"

    local SSH_SVC
    SSH_SVC=$(get_ssh_service_name)
    log_info "SSH服务名: $SSH_SVC"

    # 备份原配置
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
    # 关键: 清理行尾 \r，防止 Bad configuration option
    strip_cr "$SSHD_CONFIG"

    # ---- 使用 safe_replace 函数，精确控制每个配置项 ----

    # 1. 显式开启 PubkeyAuthentication
    safe_replace "$SSHD_CONFIG" "PubkeyAuthentication" "PubkeyAuthentication yes"

    # 2. 设置 AuthorizedKeysFile
    safe_replace "$SSHD_CONFIG" "AuthorizedKeysFile" "AuthorizedKeysFile .ssh/authorized_keys"

    # 3. 允许root密钥登录（禁止密码登录到root）
    safe_replace "$SSHD_CONFIG" "PermitRootLogin" "PermitRootLogin prohibit-password"

    # 4. 禁用密码认证
    safe_replace "$SSHD_CONFIG" "PasswordAuthentication" "PasswordAuthentication no"

    # 5. 禁用空密码
    safe_replace "$SSHD_CONFIG" "PermitEmptyPasswords" "PermitEmptyPasswords no"

    # 6. 禁用 ChallengeResponseAuthentication
    safe_replace "$SSHD_CONFIG" "ChallengeResponseAuthentication" "ChallengeResponseAuthentication no"

    # 7. 禁用 UsePAM (sshd_config 中保留 UsePAM yes 通常更安全)
    # safe_replace "$SSHD_CONFIG" "UsePAM" "UsePAM yes"

    # 8. 端口: 注释掉 Port 22，添加新端口
    # 注释 Port 22
    sed -i 's/^Port 22$/Port 43916/' "$SSHD_CONFIG" 2>/dev/null || true

    # 检查新端口是否已存在
    if ! grep -qE "^Port\s+$SSH_PORT\s*$" "$SSHD_CONFIG"; then
        # 检查 Port 43916（被替换后的旧端口）是否存在，如存在则替换
        if grep -qE "^Port\s+43916\s*$" "$SSHD_CONFIG"; then
            sed -i "s/^Port 43916$/Port $SSH_PORT/" "$SSHD_CONFIG"
            log_info "已更新端口: $SSH_PORT"
        else
            echo "Port $SSH_PORT" >> "$SSHD_CONFIG"
            log_info "已添加端口: $SSH_PORT"
        fi
    else
        log_info "端口 $SSH_PORT 已存在"
    fi

    # 9. 禁用 GSSAPI 认证（可选，减少认证开销）
    safe_replace "$SSHD_CONFIG" "GSSAPIAuthentication" "GSSAPIAuthentication no"

    # 10. 禁用 X11 Forwarding（如果不是必需的）
    safe_replace "$SSHD_CONFIG" "X11Forwarding" "X11Forwarding no"

    # 最后再清理一次 \r
    strip_cr "$SSHD_CONFIG"

    log_success "SSH配置完成"
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
        # 找出具体是哪一行的问题
        local err_line=$( "$sshd_bin" -t 2>&1 | grep -oP 'line \d+' | head -1)
        if [[ -n "$err_line" ]]; then
            local num=$(echo "$err_line" | grep -oP '\d+')
            log_error "问题出现在配置文件第 $num 行:"
            sed -n "${num}p" "$SSHD_CONFIG"
        fi
        return 1
    fi
}

#===============================================================
# 配置 fail2ban
#===============================================================
setup_fail2ban() {
    log_step "配置fail2ban"

    fix_fail2ban_deps || {
        log_warn "fail2ban 安装失败，跳过"
        return 0
    }

    [[ $FAIL2BAN_INSTALLED -eq 0 ]] && log_warn "fail2ban 未安装，跳过" && return

    local FAIL2BAN_CONF="/etc/fail2ban/jail.local"
    mkdir -p /etc/fail2ban

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
logpath = /var/log/auth.log
backend = auto
maxretry = 1
findtime = 300
bantime = -1
ignoreip = 127.0.0.1/8 ::1
EOF

    log_info "fail2ban 配置已创建"

    # 查找 fail2ban 服务名
    local fb_svc="fail2ban"
    for svc in fail2ban fail2ban-ssh sshd-fail2ban; do
        if systemctl list-unit-files "$svc.service" &>/dev/null 2>&1; then
            fb_svc="$svc"
            break
        fi
        [[ -f "/etc/init.d/$svc" ]] && fb_svc="$svc" && break
    done

    log_info "fail2ban 服务名: $fb_svc"

    service_enable "$fb_svc"
    service_start "$fb_svc"

    sleep 2

    # 验证
    if command -v fail2ban-client &>/dev/null; then
        if fail2ban-client ping &>/dev/null 2>&1; then
            log_success "fail2ban 服务运行正常"
        else
            log_warn "fail2ban ping 失败，尝试查看状态:"
            fail2ban-client status 2>&1 | head -10
        fi
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

    test_ssh_config || {
        echo -n "SSH配置测试失败，是否强制重启？(y/N): "
        read -r confirm
        if [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]]; then
            log_error "已取消重启"
            exit 1
        fi
        log_warn "强制继续..."
    }

    service_restart "$SSH_SVC"
    sleep 2

    if service_status "$SSH_SVC"; then
        log_success "SSH服务重启成功"
    else
        log_error "SSH服务可能未正常运行"
        log_info "请通过控制台检查: systemctl status $SSH_SVC"
        log_info "手动查看日志: journalctl -u $SSH_SVC -n 20 --no-pager"
    fi
}

#===============================================================
# 显示总结
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
    echo "  1. 请务必保存好SSH私钥"
    echo "  2. 新连接命令: ssh -p $SSH_PORT root@服务器IP"
    echo "  3. 连接失败请通过VNC/控制台检查"
    echo "  4. 防火墙未配置，请根据需要手动设置"
    echo ""

    [[ $FAIL2BAN_INSTALLED -eq 1 ]] && {
        echo "fail2ban 状态检查: fail2ban-client status sshd"
        echo ""
    }

    log_warn "请现在就测试SSH连接，确保能正常登录后再断开当前连接！"
}

#===============================================================
# 主函数
#===============================================================
main() {
    echo "================================================"
    echo "  服务器安全配置一键部署脚本 v2.1"
    echo "  修复: CRLF问题 / SSH配置 / fail2ban兼容"
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
    log_info "开始执行配置..."
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
