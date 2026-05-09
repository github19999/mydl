#密钥登录   禁止密码登录(不重写文件)   改变端口   BBR   fail2ban安装启用   IPv4/IPv6优先级配置   IPv4/IPv6禁用配置
#版本: v1.0 - 适配所有服务器环境

#!/bin/bash

#===============================================================
# 颜色定义
#===============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

#===============================================================
# 日志函数
#===============================================================
log_info()   { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()  { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()   { echo -e "${BLUE}[STEP]${NC} $1"; }
log_success(){ echo -e "${CYAN}[OK]${NC} $1"; }

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
    log_info "检测到初始化系统: $INIT_SYSTEM"
}

#===============================================================
# 检测发行版和包管理器
#===============================================================
detect_os_and_pkg_manager() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_ID_LIKE="$ID_LIKE"
        OS_NAME="$NAME"
        OS_VERSION="$VERSION_ID"
    else
        OS_ID="unknown"
        OS_ID_LIKE=""
        OS_NAME="Unknown"
        OS_VERSION=""
    fi
    log_info "操作系统: $OS_NAME ($OS_VERSION), ID: $OS_ID"

    # 检测包管理器
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
# 检查root权限
#===============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

#===============================================================
# 检测 SSH 服务名 (兼容systemd/sysvinit/OpenRC)
#===============================================================
get_ssh_service_name() {
    if systemctl list-unit-files sshd.service &>/dev/null; then
        echo "sshd"
    elif systemctl list-unit-files ssh.service &>/dev/null; then
        echo "ssh"
    elif [[ -f /etc/init.d/sshd ]]; then
        echo "sshd"
    elif [[ -f /etc/init.d/ssh ]]; then
        echo "ssh"
    elif [[ -f /etc/init.d/fail2ban ]]; then
        # OpenRC 下可能是 fail2ban
        echo "fail2ban"
    elif ls /etc/init.d/ssh* &>/dev/null; then
        ls /etc/init.d/ssh* 2>/dev/null | head -1 | xargs basename
    else
        echo "sshd"  # 默认值
    fi
}

#===============================================================
# 通用服务管理函数 (兼容systemd/sysvinit/OpenRC)
#===============================================================
service_enable() {
    local service="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl enable "$service" 2>/dev/null
            ;;
        sysvinit|OpenRC)
            update-rc.d "$service" defaults 2>/dev/null || \
            rc-update add "$service" default 2>/dev/null || \
            ln -sf "/etc/init.d/$service" "/etc/rc3.d/S99$service" 2>/dev/null || true
            ;;
    esac
}

service_start() {
    local service="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl start "$service" 2>/dev/null
            ;;
        sysvinit|OpenRC)
            /etc/init.d/"$service" start 2>/dev/null || service "$service" start 2>/dev/null || true
            ;;
    esac
}

service_restart() {
    local service="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl restart "$service" 2>/dev/null
            ;;
        sysvinit|OpenRC)
            /etc/init.d/"$service" restart 2>/dev/null || service "$service" restart 2>/dev/null || true
            ;;
    esac
}

service_status() {
    local service="$1"
    case $INIT_SYSTEM in
        systemd)
            systemctl status "$service" &>/dev/null && return 0 || return 1
            ;;
        sysvinit|OpenRC)
            /etc/init.d/"$service" status 2>/dev/null && return 0 || return 1
            ;;
    esac
}

#===============================================================
# 获取用户输入的公钥 (支持多行)
#===============================================================
get_public_key() {
    echo ""
    log_step "配置SSH密钥登录"
    echo "请输入你的SSH公钥（通常以 ssh-rsa / ssh-ed25519 / ecdsa-sha2 开头）:"
    echo "提示: 可以粘贴整行，脚本会自动处理换行和多余空格"
    echo ""
    read -r PUBLIC_KEY

    if [[ -z "$PUBLIC_KEY" ]]; then
        log_error "公钥不能为空"
        exit 1
    fi

    # 基本的公钥格式校验
    if [[ ! "$PUBLIC_KEY" =~ ^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2-nistp|sk-ssh-ed25519@openssh.com) ]]; then
        log_warn "公钥格式可能不正确，但继续执行..."
        echo "公钥内容: ${PUBLIC_KEY:0:50}..."
    fi
}

#===============================================================
# 获取新的SSH端口
#===============================================================
get_ssh_port() {
    echo ""
    log_step "配置SSH端口"
    echo "请输入新的SSH端口（建议10000-65535之间，默认43916）:"
    read -r SSH_PORT

    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT=43916
    fi

    # 验证端口是否为数字
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
        log_error "端口必须是数字"
        exit 1
    fi

    if [[ $SSH_PORT -lt 1024 || $SSH_PORT -gt 65535 ]]; then
        log_error "端口范围应在1024-65535之间"
        exit 1
    fi

    # 检查端口是否已被占用
    if ss -tlnp 2>/dev/null | grep -q ":$SSH_PORT " || netstat -tlnp 2>/dev/null | grep -q ":$SSH_PORT "; then
        log_warn "端口 $SSH_PORT 似乎已被占用，继续执行..."
    fi

    log_info "将使用SSH端口: $SSH_PORT"
}

#===============================================================
# 获取IP协议优先级配置
#===============================================================
get_ip_priority() {
    echo ""
    log_step "配置IP协议优先级"
    echo "请选择IP协议优先级设置:"
    echo "1) IPv4优先"
    echo "2) IPv6优先"
    echo "3) 保持不变"
    echo -n "请输入选择 (1-3，默认1): "
    read -r IP_PRIORITY_CHOICE

    if [[ -z "$IP_PRIORITY_CHOICE" ]]; then
        IP_PRIORITY_CHOICE=1
    fi

    case $IP_PRIORITY_CHOICE in
        1) IP_PRIORITY="ipv4"; log_info "将设置IPv4优先" ;;
        2) IP_PRIORITY="ipv6"; log_info "将设置IPv6优先" ;;
        3) IP_PRIORITY="none"; log_info "将保持IP协议优先级不变" ;;
        *) log_warn "无效选择，使用默认设置（IPv4优先）"; IP_PRIORITY="ipv4" ;;
    esac
}

#===============================================================
# 获取IP协议禁用配置
#===============================================================
get_ip_disable() {
    echo ""
    log_step "配置IP协议禁用"
    echo "请选择要禁用的IP协议:"
    echo "1) 禁用IPv6"
    echo "2) 禁用IPv4"
    echo "3) 保持不变"
    echo -n "请输入选择 (1-3，默认1): "
    read -r IP_DISABLE_CHOICE

    if [[ -z "$IP_DISABLE_CHOICE" ]]; then
        IP_DISABLE_CHOICE=1
    fi

    case $IP_DISABLE_CHOICE in
        1) IP_DISABLE="ipv6"; log_info "将禁用IPv6" ;;
        2) IP_DISABLE="ipv4"; log_info "将禁用IPv4" ;;
        3) IP_DISABLE="none"; log_info "将保持IP协议状态不变" ;;
        *) log_warn "无效选择，使用默认设置（禁用IPv6）"; IP_DISABLE="ipv6" ;;
    esac
}

#===============================================================
# 系统更新和基础软件安装 (支持多发行版)
#===============================================================
install_basics() {
    log_step "更新系统并安装基础软件"

    case $PKG_MANAGER in
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt update -y 2>&1 | tail -3
            apt install -y --no-install-recommends \
                curl sudo wget git unzip nano vim \
                fail2ban python3 python3-pip \
                ufw 2>&1 | tail -5
            ;;
        yum)
            yum install -y epel-release 2>/dev/null || true
            yum install -y curl sudo wget git unzip nano vim \
                fail2ban python3 \
                firewalld 2>&1 | tail -5
            ;;
        dnf)
            dnf install -y epel-release 2>/dev/null || true
            dnf install -y curl sudo wget git unzip nano vim \
                fail2ban python3 \
                firewalld 2>&1 | tail -5
            ;;
        pacman)
            pacman -Sy --noconfirm curl sudo wget git unzip nano vim \
                fail2ban python3 2>&1 | tail -5
            ;;
        apk)
            apk add curl sudo wget git unzip nano vim \
                fail2ban python3 2>&1 | tail -5
            ;;
        zypper)
            zypper install -y curl sudo wget git unzip nano vim \
                fail2ban python3 2>&1 | tail -5
            ;;
        *)
            log_error "不支持的包管理器: $PKG_MANAGER"
            exit 1
            ;;
    esac

    if [[ $? -eq 0 ]]; then
        log_success "基础软件安装完成"
    else
        log_warn "部分软件安装可能失败，尝试继续..."
    fi
}

#===============================================================
# 修复 fail2ban 依赖问题
#===============================================================
fix_fail2ban_deps() {
    log_step "检查并修复 fail2ban 依赖"

    # 检查 Python
    if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
        log_error "未找到 Python，安装失败"
        return 1
    fi

    local PYTHON_BIN=$(command -v python3 || command -v python)

    # 检查 fail2ban 是否可用
    if ! command -v fail2ban-client &>/dev/null; then
        log_warn "fail2ban 未安装，尝试通过 pip 安装..."
        if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
            local PIP_BIN=$(command -v pip3 || command -v pip)
            $PIP_BIN install fail2ban 2>&1 | tail -3
            if [[ $? -eq 0 ]]; then
                FAIL2BAN_INSTALLED=1
                log_success "fail2ban 通过 pip 安装成功"
            else
                log_error "fail2ban pip 安装失败"
                return 1
            fi
        else
            log_error "无法安装 fail2ban，pip 未找到"
            return 1
        fi
    else
        FAIL2BAN_INSTALLED=1
        log_success "fail2ban 已安装"
    fi
}

#===============================================================
# 启用BBR加速 (带兼容性检查)
#===============================================================
enable_bbr() {
    log_step "启用BBR拥塞控制算法"

    # 检查是否已经启用BBR
    current_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    current_qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')

    if [[ "$current_congestion" == "bbr" ]] && [[ "$current_qdisc" == "fq" ]]; then
        log_info "BBR已经启用 (qdisc=$current_qdisc, congestion=$current_congestion)"
        return
    fi

    # 检查内核模块是否可用
    if ! modprobe tcp_bbr 2>/dev/null; then
        log_warn "tcp_bbr 模块可能不可用（内核版本需>=4.9），尝试继续..."
    fi

    # 避免重复写入相同配置
    if grep -q "net.core.default_qdisc=fq" "$SYSCTL_CONF" 2>/dev/null; then
        log_info "BBR qdisc配置已存在"
    else
        echo "net.core.default_qdisc=fq" >> "$SYSCTL_CONF"
    fi

    if grep -q "net.ipv4.tcp_congestion_control=bbr" "$SYSCTL_CONF" 2>/dev/null; then
        log_info "BBR congestion控制配置已存在"
    else
        echo "net.ipv4.tcp_congestion_control=bbr" >> "$SYSCTL_CONF"
    fi

    sysctl -p >/dev/null 2>&1

    # 验证
    new_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$new_congestion" == "bbr" ]]; then
        log_success "BBR启用成功"
    else
        log_warn "BBR可能需要更高内核版本，当前内核: $(uname -r)"
        log_warn "BBR配置已写入，重启后将生效"
    fi
}

#===============================================================
# 设置IP协议优先级
#===============================================================
set_ip_priority() {
    if [[ "$IP_PRIORITY" == "none" ]]; then
        log_info "跳过IP协议优先级设置"
        return
    fi

    log_step "设置IP协议优先级"

    local GAI_CONF="/etc/gai.conf"
    # 部分系统上是 /etc/gai.conf，部分是 ~/.gairc
    if [[ ! -f "$GAI_CONF" ]]; then
        GAI_CONF="/etc/gai.conf"  # 尝试创建
    fi

    if [[ ! -f "$GAI_CONF" ]]; then
        log_warn "/etc/gai.conf 文件不存在，跳过优先级设置"
        return
    fi

    cp "$GAI_CONF" "${GAI_CONF}.backup.$(date +%Y%m%d_%H%M%S)"

    if [[ "$IP_PRIORITY" == "ipv4" ]]; then
        if grep -q "^precedence ::ffff:0:0/96" "$GAI_CONF"; then
            # 确保未注释
            sed -i 's/^#precedence/precedence/' "$GAI_CONF"
            log_success "IPv4优先已启用"
        elif grep -q "^#precedence ::ffff:0:0/96" "$GAI_CONF"; then
            sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' "$GAI_CONF"
            log_success "IPv4优先已启用（取消注释）"
        else
            echo "precedence ::ffff:0:0/96  100" >> "$GAI_CONF"
            log_success "IPv4优先已添加"
        fi
    elif [[ "$IP_PRIORITY" == "ipv6" ]]; then
        if grep -q "^precedence ::ffff:0:0/96" "$GAI_CONF"; then
            sed -i 's/^precedence ::ffff:0:0\/96  100/#precedence ::ffff:0:0\/96  100/' "$GAI_CONF"
            log_success "IPv6优先已设置（注释IPv4优先）"
        else
            log_info "IPv6优先已生效（无IPv4优先配置）"
        fi
    fi
}

#===============================================================
# 禁用指定的IP协议
#===============================================================
disable_ip_protocol() {
    if [[ "$IP_DISABLE" == "none" ]]; then
        log_info "跳过IP协议禁用设置"
        return
    fi

    log_step "禁用IP协议"

    cp "$SYSCTL_CONF" "${SYSCTL_CONF}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

    if [[ "$IP_DISABLE" == "ipv6" ]]; then
        if grep -q "net.ipv6.conf.all.disable_ipv6=1" "$SYSCTL_CONF" 2>/dev/null; then
            log_info "IPv6禁用配置已存在"
            return
        fi

        cat >> "$SYSCTL_CONF" << EOF

# IPv6 disabled by script
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF

        sysctl -p >/dev/null 2>&1

        if [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null) == "1" ]]; then
            log_success "IPv6已成功禁用"
        else
            log_warn "IPv6禁用可能需要重启系统后生效"
        fi

    elif [[ "$IP_DISABLE" == "ipv4" ]]; then
        log_warn "禁用IPv4是危险操作，可能导致系统无法访问！"
        echo -n "确定要禁用IPv4吗？(y/N): "
        read -r confirm

        if [[ "$confirm" == "y" ]] || [[ "$confirm" == "Y" ]]; then
            if grep -q "net.ipv4.conf.all.disable_ipv4=1" "$SYSCTL_CONF" 2>/dev/null; then
                log_info "IPv4禁用配置已存在"
                return
            fi

            cat >> "$SYSCTL_CONF" << EOF

# IPv4 disabled by script
net.ipv4.conf.all.disable_ipv4=1
net.ipv4.conf.default.disable_ipv4=1
EOF

            log_warn "IPv4禁用配置已添加，重启后生效"
        else
            log_info "已取消IPv4禁用操作"
            IP_DISABLE="none"
        fi
    fi
}

#===============================================================
# 配置SSH密钥登录 (关键优化)
#===============================================================
setup_ssh_key() {
    log_step "配置SSH密钥登录"

    # 清理公钥中的多余空白字符和换行，统一成单行
    PUBLIC_KEY=$(echo "$PUBLIC_KEY" | tr -d '\r' | awk '{printf "%s", $0}' | sed 's/[[:space:]]*$//')

    # 获取SSH服务运行的用户，通常是 root 或 ubuntu
    SSH_USER="root"
    SSH_HOME="/root"
    USER_HOME=$(getent passwd "$(whoami)" | cut -d: -f6)
    if [[ "$EUID" -eq 0 ]]; then
        # 如果以root运行，检查是否存在目标用户的家目录
        if [[ -d "$USER_HOME" ]] && [[ "$USER_HOME" != "/root" ]]; then
            log_info "检测到非root用户环境: $USER_HOME"
            SSH_USER=$(whoami)
            SSH_HOME="$USER_HOME"
        fi
    fi

    log_info "SSH密钥将配置到用户: $SSH_USER ($SSH_HOME)"

    # 创建 .ssh 目录并设置正确权限
    mkdir -p "$SSH_HOME/.ssh"
    chmod 700 "$SSH_HOME/.ssh"

    # 追加公钥到 authorized_keys (保留已有密钥)
    if grep -Fq "$PUBLIC_KEY" "$SSH_HOME/.ssh/authorized_keys" 2>/dev/null; then
        log_info "此公钥已存在于 authorized_keys"
    else
        echo "$PUBLIC_KEY" >> "$SSH_HOME/.ssh/authorized_keys"
        log_info "公钥已添加到 authorized_keys"
    fi

    # 设置正确权限
    chmod 600 "$SSH_HOME/.ssh/authorized_keys"
    chown -R "$SSH_USER:$SSH_USER" "$SSH_HOME/.ssh"

    log_success "SSH密钥配置完成"
}

#===============================================================
# 配置SSH安全设置 (关键优化)
#===============================================================
configure_ssh() {
    log_step "配置SSH安全设置"

    local SSH_SERVICE
    SSH_SERVICE=$(get_ssh_service_name)
    log_info "检测到SSH服务名: $SSH_SERVICE"

    # 备份
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"

    # --- 使用sed精确修改配置 ---

    # 1. 设置 PubkeyAuthentication 为 yes (显式开启，避免默认值被忽略)
    if grep -qE "^\s*PubkeyAuthentication\s+" "$SSHD_CONFIG"; then
        sed -i 's/^\s*PubkeyAuthentication\s\+.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
    elif grep -qE "^#\s*PubkeyAuthentication" "$SSHD_CONFIG"; then
        sed -i 's/^#\s*PubkeyAuthentication/PubkeyAuthentication/' "$SSHD_CONFIG"
    else
        echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
    fi

    # 2. 设置 AuthorizedKeysFile (兼容多系统)
    if grep -qE "^\s*AuthorizedKeysFile\s+" "$SSHD_CONFIG"; then
        # 已存在，跳过
        log_info "AuthorizedKeysFile 已配置"
    else
        echo "AuthorizedKeysFile .ssh/authorized_keys" >> "$SSHD_CONFIG"
    fi

    # 3. 设置 PermitRootLogin (允许root登录用于密钥认证)
    if grep -qE "^\s*PermitRootLogin\s+" "$SSHD_CONFIG"; then
        sed -i 's/^\s*PermitRootLogin\s\+.*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"
    elif grep -qE "^#\s*PermitRootLogin" "$SSHD_CONFIG"; then
        sed -i 's/^#\s*PermitRootLogin/PermitRootLogin/' "$SSHD_CONFIG"
    else
        echo "PermitRootLogin prohibit-password" >> "$SSHD_CONFIG"
    fi

    # 4. 禁用密码认证
    if grep -qE "^\s*PasswordAuthentication\s+" "$SSHD_CONFIG"; then
        sed -i 's/^\s*PasswordAuthentication\s\+.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    elif grep -qE "^#\s*PasswordAuthentication" "$SSHD_CONFIG"; then
        sed -i 's/^#\s*PasswordAuthentication/PasswordAuthentication/' "$SSHD_CONFIG"
    else
        echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
    fi

    # 5. 禁用空密码登录
    if grep -qE "^\s*PermitEmptyPasswords\s+" "$SSHD_CONFIG"; then
        sed -i 's/^\s*PermitEmptyPasswords\s\+.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
    else
        echo "PermitEmptyPasswords no" >> "$SSHD_CONFIG"
    fi

    # 6. 设置 ChallengeResponseAuthentication
    if grep -qE "^\s*ChallengeResponseAuthentication\s+" "$SSHD_CONFIG"; then
        sed -i 's/^\s*ChallengeResponseAuthentication\s\+.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
    else
        echo "ChallengeResponseAuthentication no" >> "$SSHD_CONFIG"
    fi

    # 7. 设置 UsePAM
    if grep -qE "^\s*UsePAM\s+" "$SSHD_CONFIG"; then
        sed -i 's/^\s*UsePAM\s\+.*/UsePAM yes/' "$SSHD_CONFIG"
    else
        echo "UsePAM yes" >> "$SSHD_CONFIG"
    fi

    # 8. 修改端口 - 注释掉原 Port 22，添加新端口
    if grep -qE "^Port\s+22\s*" "$SSHD_CONFIG"; then
        sed -i 's/^Port\s\+22\s*/#Port 22/' "$SSHD_CONFIG"
        log_info "已注释原 Port 22"
    fi

    if ! grep -qE "^Port\s+$SSH_PORT\s*" "$SSHD_CONFIG"; then
        echo "Port $SSH_PORT" >> "$SSHD_CONFIG"
        log_info "已添加新端口配置: $SSH_PORT"
    else
        log_info "端口 $SSH_PORT 已存在"
    fi

    # 9. 设置 PubkeyAcceptedAlgorithms / PubkeyAcceptedKeyTypes (兼容新旧客户端)
    # 新的 openssh 版本使用 PubkeyAcceptedAlgorithms，旧的使用 PubkeyAcceptedKeyTypes
    if ! grep -qE "^PubkeyAcceptedAlgorithms" "$SSHD_CONFIG" && \
       ! grep -qE "^PubkeyAcceptedKeyTypes" "$SSHD_CONFIG"; then
        echo "PubkeyAcceptedAlgorithms ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519" >> "$SSHD_CONFIG"
    fi

    log_success "SSH配置完成 (端口: $SSH_PORT, 密钥登录: 已启用, 密码登录: 已禁用)"
}

#===============================================================
# 测试SSH配置 (兼容多路径)
#===============================================================
test_ssh_config() {
    log_step "测试SSH配置"

    # 尝试找到 sshd 二进制文件
    local SSHD_BIN=""
    for path in /usr/sbin/sshd /usr/sbin/sshd /sbin/sshd /etc/sbin/sshd; do
        if [[ -x "$path" ]]; then
            SSHD_BIN="$path"
            break
        fi
    done

    # 如果找不到，尝试 which
    if [[ -z "$SSHD_BIN" ]]; then
        SSHD_BIN=$(command -v sshd 2>/dev/null)
    fi

    if [[ -z "$SSHD_BIN" ]]; then
        log_warn "未找到 sshd 二进制文件，跳过配置测试"
        log_warn "请稍后手动测试: sshd -t"
        return 0
    fi

    if "$SSHD_BIN" -t 2>&1; then
        log_success "SSH配置测试通过"
        return 0
    else
        log_error "SSH配置测试失败，查看错误:"
        "$SSHD_BIN" -t 2>&1
        return 1
    fi
}

#===============================================================
# 配置 fail2ban (关键优化 - 多初始化系统支持)
#===============================================================
setup_fail2ban() {
    log_step "配置fail2ban"

    # 修复依赖
    fix_fail2ban_deps || {
        log_warn "fail2ban 安装失败，跳过配置"
        return 0
    }

    if [[ $FAIL2BAN_INSTALLED -eq 0 ]]; then
        log_warn "fail2ban 未安装，跳过"
        return 0
    fi

    local FAIL2BAN_CONF_DIR="/etc/fail2ban"
    local FAIL2BAN_LOCAL="/etc/fail2ban/jail.local"

    # 创建配置目录
    mkdir -p "$FAIL2BAN_CONF_DIR"

    # 创建 jail.local 配置
    cat > "$FAIL2BAN_LOCAL" << EOF
[DEFAULT]
# 忽略的IP地址
ignoreip = 127.0.0.1/8 ::1

# 禁止时间（-1=永久）
bantime = -1

# 检测时间窗口（秒）
findtime = 300

# 最大重试次数
maxretry = 1

# 日志级别
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

    log_info "fail2ban 配置文件已创建"

    # 根据初始化系统启用并启动
    local FAIL2BAN_SERVICE=""
    for svc in fail2ban fail2ban-ssh sshd-fail2ban; do
        if [[ -f "/etc/init.d/$svc" ]] || \
           systemctl list-unit-files "$svc.service" &>/dev/null 2>&1; then
            FAIL2BAN_SERVICE="$svc"
            break
        fi
    done

    if [[ -z "$FAIL2BAN_SERVICE" ]]; then
        FAIL2BAN_SERVICE="fail2ban"
    fi

    log_info "fail2ban 服务名: $FAIL2BAN_SERVICE"

    # 启用服务
    service_enable "$FAIL2BAN_SERVICE"

    # 启动/重启服务
    service_restart "$FAIL2BAN_SERVICE"
    sleep 1

    # 验证服务状态
    if command -v fail2ban-client &>/dev/null; then
        if fail2ban-client ping &>/dev/null; then
            log_success "fail2ban 服务运行正常"
        else
            log_warn "fail2ban ping 失败，服务可能未正常运行"
        fi
    else
        log_warn "fail2ban-client 不可用，跳过状态检查"
    fi
}

#===============================================================
# 重启SSH服务 (兼容多初始化系统)
#===============================================================
restart_ssh() {
    log_step "重启SSH服务"

    local SSH_SERVICE
    SSH_SERVICE=$(get_ssh_service_name)
    log_info "重启SSH服务: $SSH_SERVICE"

    # 测试配置
    test_ssh_config || {
        log_error "SSH配置测试失败，不建议重启服务"
        echo -n "是否强制重启？(y/N): "
        read -r confirm
        if [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]]; then
            log_error "已取消重启"
            exit 1
        fi
        log_warn "强制继续重启..."
    }

    service_restart "$SSH_SERVICE"
    sleep 2

    # 验证服务状态
    if service_status "$SSH_SERVICE"; then
        log_success "SSH服务重启成功"
    else
        log_error "SSH服务可能未正常启动"
        log_info "请通过控制台检查: systemctl status $SSH_SERVICE"
    fi
}

#===============================================================
# 显示配置总结
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
    echo "  - 初始化系统:         $INIT_SYSTEM"
    echo "  - 包管理器:           $PKG_MANAGER"
    echo "  - fail2ban:           $([[ $FAIL2BAN_INSTALLED -eq 1 ]] && echo "已安装" || echo "未安装")"

    case $IP_PRIORITY in
        "ipv4") echo "  - IP协议优先级:      IPv4优先" ;;
        "ipv6") echo "  - IP协议优先级:      IPv6优先" ;;
        "none") echo "  - IP协议优先级:      保持不变" ;;
    esac

    case $IP_DISABLE in
        "ipv4") echo "  - IP协议状态:        IPv4已禁用" ;;
        "ipv6") echo "  - IP协议状态:        IPv6已禁用" ;;
        "none") echo "  - IP协议状态:        保持不变" ;;
    esac

    echo ""
    echo "重要提醒："
    echo "  1. 请务必保存好你的SSH私钥"
    echo "  2. 新的SSH连接命令: ssh -p $SSH_PORT root@服务器IP"
    echo "  3. 如果连接失败，请通过VNC/控制台登录检查"
    echo "  4. 防火墙未配置，请根据需要手动设置"
    echo ""

    if [[ $FAIL2BAN_INSTALLED -eq 1 ]]; then
        echo "fail2ban 状态检查命令："
        echo "  fail2ban-client status sshd"
        echo ""
    fi

    log_warn "请现在就测试SSH连接，确保能正常登录后再断开当前连接！"
}

#===============================================================
# 主函数
#===============================================================
main() {
    echo "================================================"
    echo "   服务器安全配置一键部署脚本 v2.0"
    echo "   适配所有服务器环境"
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

# 执行主函数
main "$@"
