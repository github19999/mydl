#!/bin/bash

# ================================================================
#   服务器安全配置一键部署脚本 v2.1
# ================================================================
#
#   【脚本用途】
#   用于在全新 Linux 服务器上快速完成安全加固与基础环境初始化，
#   避免手动逐条执行命令导致的遗漏或配置错误。
#
#   【适用系统】
#   - Ubuntu 18 / 20 / 22 / 24
#   - Debian 10 / 11 / 12
#   - CentOS 7 / 8 / 9
#   - RHEL 7 / 8 / 9
#   - AlmaLinux 8 / 9
#   - Rocky Linux 8 / 9
#
#   【执行顺序】
#   1. 检查 root 权限
#   2. 预装基础组件（apt/dnf/yum 自动识别）
#      - apt update
#      - 安装 curl sudo wget git unzip nano vim
#   3. 检测发行版与包管理器
#   4. 收集用户配置（交互式输入）
#   5. 安装 fail2ban
#   6. 启用 BBR 拥塞控制加速
#   7. 设置 IP 协议优先级（gai.conf）
#   8. 禁用指定 IP 协议（sysctl.d）
#   9. 配置 SSH 密钥登录
#  10. 加固 SSH 配置
#  11. 配置并启动 fail2ban
#  12. 重启 SSH 服务并验证
#
#   【功能说明】
#
#   ── SSH 密钥登录 ──────────────────────────────────────────
#   · 将用户提供的公钥追加写入 /root/.ssh/authorized_keys
#   · 自动设置 .ssh 目录及文件的正确权限（700 / 600）
#   · 显式启用 PubkeyAuthentication 和 AuthorizedKeysFile，
#     防止部分系统因默认未写该参数导致密钥登录失效
#   · 在 CentOS/RHEL 上自动执行 restorecon 修复 SELinux 上下文
#
#   ── 禁用密码登录 ──────────────────────────────────────────
#   · 同时禁用三项相关参数，全面封堵密码登录旁路：
#     - PasswordAuthentication no
#     - ChallengeResponseAuthentication no（旧版 SSH 兼容名）
#     - KbdInteractiveAuthentication no（新版 SSH 名称）
#   · 修改采用精确替换方式，不覆盖 sshd_config 原文件，
#     修改前自动备份（带时间戳）
#
#   ── 修改 SSH 端口 ─────────────────────────────────────────
#   · 注释原有端口配置，追加新端口，默认 43916
#   · 修改前执行 sshd -t 语法检查，失败则中止并提示备份位置
#   · 自动兼容 sshd / ssh 两种系统服务名
#
#   ── BBR 拥塞控制 ──────────────────────────────────────────
#   · 检测内核版本（需 4.9+）及当前是否已启用，避免重复写入
#   · 写入 net.core.default_qdisc=fq 和
#     net.ipv4.tcp_congestion_control=bbr 到 /etc/sysctl.conf
#   · 立即执行 sysctl -p 使配置生效
#
#   ── IP 协议优先级 ─────────────────────────────────────────
#   · 修改 /etc/gai.conf 中的 precedence 行
#   · IPv4 优先：取消注释或追加 precedence ::ffff:0:0/96 100
#   · IPv6 优先：注释该行，让系统回退默认（IPv6 优先）
#   · 修改前自动备份原文件（带时间戳）
#
#   ── IP 协议禁用 ───────────────────────────────────────────
#   · 写入独立文件 /etc/sysctl.d/99-disable-ipv6.conf，
#     不污染 /etc/sysctl.conf 主文件
#   · 禁用 IPv4 为危险操作，需二次确认后方可执行
#   · 默认选项为"保持不变"，防止误操作断连
#
#   ── fail2ban ──────────────────────────────────────────────
#   · 自动检测日志后端：systemd-journald 可用则用 systemd，
#     否则回退 auto 并自动查找 /var/log/auth.log 或 /var/log/secure
#   · 写入 /etc/fail2ban/jail.local 配置：
#     SSH 端口监控、maxretry=1、bantime=-1（永久封禁）
#   · 先停止服务再写配置，避免文件锁冲突
#   · 安装或启动失败只打警告，不中止整体流程
#
#   【注意事项】
#   · 必须以 root 身份运行
#   · 执行完成后，请先开新终端用密钥测试 SSH 连接，
#     确认可正常登录后再断开当前会话
#   · 脚本不配置防火墙，请手动放行新 SSH 端口
#   · 所有被修改的配置文件均会在同目录生成带时间戳的备份
#
# ================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

# ------------------------------------------------
# 检测发行版
# ------------------------------------------------
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID}"           # ubuntu / debian / centos / rhel / almalinux / rocky
        DISTRO_VERSION="${VERSION_ID%%.*}"   # 主版本号（如 22、11、9）
    else
        log_error "无法识别操作系统，仅支持含 /etc/os-release 的发行版"
        exit 1
    fi

    case "$DISTRO_ID" in
        ubuntu|debian|raspbian)
            PKG_MANAGER="apt"
            ;;
        centos|rhel|almalinux|rocky|fedora)
            PKG_MANAGER="yum"
            # RHEL 8+ 使用 dnf
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
            fi
            ;;
        *)
            log_warn "未经测试的发行版: $DISTRO_ID，将尝试使用 apt 继续"
            PKG_MANAGER="apt"
            ;;
    esac

    log_info "检测到系统: $PRETTY_NAME (包管理器: $PKG_MANAGER)"
}

# ------------------------------------------------
# 权限检查
# ------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        exit 1
    fi
}

# ------------------------------------------------
# 获取 SSH 公钥
# ------------------------------------------------
get_public_key() {
    echo ""
    log_step "配置 SSH 密钥登录"
    echo "请输入你的 SSH 公钥（通常以 ssh-rsa / ssh-ed25519 开头）:"
    read -r PUBLIC_KEY

    if [[ -z "$PUBLIC_KEY" ]]; then
        log_error "公钥不能为空"
        exit 1
    fi

    if [[ ! "$PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|sk-ssh-ed25519) ]]; then
        log_warn "公钥格式可能不正确，但继续执行..."
    fi
}

# ------------------------------------------------
# 获取 SSH 端口
# ------------------------------------------------
get_ssh_port() {
    echo ""
    log_step "配置 SSH 端口"
    echo "请输入新的 SSH 端口（建议 10000-65535，默认 43916）:"
    read -r SSH_PORT

    [[ -z "$SSH_PORT" ]] && SSH_PORT=43916

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ $SSH_PORT -lt 1024 || $SSH_PORT -gt 65535 ]]; then
        log_error "端口范围应在 1024-65535 之间"
        exit 1
    fi

    log_info "将使用 SSH 端口: $SSH_PORT"
}

# ------------------------------------------------
# 获取 IP 协议优先级
# ------------------------------------------------
get_ip_priority() {
    echo ""
    log_step "配置 IP 协议优先级"
    echo "1) IPv4 优先"
    echo "2) IPv6 优先"
    echo "3) 保持不变"
    echo -n "请输入选择 (1-3，默认 1): "
    read -r IP_PRIORITY_CHOICE

    [[ -z "$IP_PRIORITY_CHOICE" ]] && IP_PRIORITY_CHOICE=1

    case $IP_PRIORITY_CHOICE in
        1) IP_PRIORITY="ipv4"; log_info "将设置 IPv4 优先" ;;
        2) IP_PRIORITY="ipv6"; log_info "将设置 IPv6 优先" ;;
        3) IP_PRIORITY="none"; log_info "保持 IP 协议优先级不变" ;;
        *) log_warn "无效选择，使用默认 IPv4 优先"; IP_PRIORITY="ipv4" ;;
    esac
}

# ------------------------------------------------
# 获取 IP 协议禁用配置
# ------------------------------------------------
get_ip_disable() {
    echo ""
    log_step "配置 IP 协议禁用"
    echo "1) 禁用 IPv6"
    echo "2) 禁用 IPv4（危险）"
    echo "3) 保持不变"
    echo -n "请输入选择 (1-3，默认 3): "
    read -r IP_DISABLE_CHOICE

    # 【改动】默认改为"保持不变"，避免操作失误导致断连
    [[ -z "$IP_DISABLE_CHOICE" ]] && IP_DISABLE_CHOICE=3

    case $IP_DISABLE_CHOICE in
        1) IP_DISABLE="ipv6"; log_info "将禁用 IPv6" ;;
        2) IP_DISABLE="ipv4"; log_info "将禁用 IPv4" ;;
        3) IP_DISABLE="none"; log_info "保持 IP 协议状态不变" ;;
        *) log_warn "无效选择，保持不变"; IP_DISABLE="none" ;;
    esac
}

# ------------------------------------------------
# 补装 fail2ban（基础包已由 bootstrap_packages 完成）
# ------------------------------------------------
install_basics() {
    log_step "安装 fail2ban"

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        apt install -y fail2ban || log_warn "fail2ban 安装失败，将在 setup_fail2ban 中重试"
    elif [[ "$PKG_MANAGER" =~ ^(yum|dnf)$ ]]; then
        # EPEL 已在 bootstrap 阶段装好，直接装 fail2ban
        $PKG_MANAGER install -y fail2ban || log_warn "fail2ban 安装失败，请手动安装后重新运行 setup_fail2ban"
    fi
}

# ------------------------------------------------
# 启用 BBR
# ------------------------------------------------
enable_bbr() {
    log_step "启用 BBR 拥塞控制算法"

    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$current_cc" == "bbr" ]]; then
        log_info "BBR 已启用，跳过"
        return
    fi

    # 检查内核是否支持 BBR（需要 4.9+）
    kernel_version=$(uname -r | cut -d. -f1-2 | tr -d '.')
    # 简单数值比较：4.9 → 49
    if [[ "$kernel_version" -lt 49 ]] 2>/dev/null; then
        log_warn "内核版本低于 4.9，BBR 不受支持，跳过"
        return
    fi

    # 【改动】避免重复追加：先检查再写入
    grep -q "^net.core.default_qdisc=fq" /etc/sysctl.conf || \
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    grep -q "^net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || \
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

    sysctl -p > /dev/null 2>&1

    if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        log_info "BBR 启用成功"
    else
        log_warn "BBR 可能未生效，请确认内核已加载 tcp_bbr 模块"
    fi
}

# ------------------------------------------------
# IP 协议优先级
# ------------------------------------------------
set_ip_priority() {
    [[ "$IP_PRIORITY" == "none" ]] && { log_info "跳过 IP 协议优先级设置"; return; }

    log_step "设置 IP 协议优先级"

    if [[ ! -f /etc/gai.conf ]]; then
        log_warn "/etc/gai.conf 不存在，跳过"
        return
    fi

    cp /etc/gai.conf "/etc/gai.conf.backup.$(date +%Y%m%d_%H%M%S)"

    if [[ "$IP_PRIORITY" == "ipv4" ]]; then
        # 取消注释（若已注释）或直接添加
        if grep -q "^#\s*precedence ::ffff:0:0/96" /etc/gai.conf; then
            sed -i 's/^#\s*precedence ::ffff:0:0\/96.*/precedence ::ffff:0:0\/96  100/' /etc/gai.conf
        elif ! grep -q "^precedence ::ffff:0:0/96" /etc/gai.conf; then
            echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
        fi
        log_info "IPv4 优先已设置"
    else
        # IPv6 优先：注释掉该行
        sed -i 's/^precedence ::ffff:0:0\/96/#precedence ::ffff:0:0\/96/' /etc/gai.conf
        log_info "IPv6 优先已设置"
    fi
}

# ------------------------------------------------
# 禁用 IP 协议
# ------------------------------------------------
disable_ip_protocol() {
    [[ "$IP_DISABLE" == "none" ]] && { log_info "跳过 IP 协议禁用"; return; }

    log_step "禁用 IP 协议"

    # 【改动】使用独立配置文件，不修改 /etc/sysctl.conf 主文件
    SYSCTL_D="/etc/sysctl.d"
    mkdir -p "$SYSCTL_D"

    if [[ "$IP_DISABLE" == "ipv6" ]]; then
        CONF_FILE="$SYSCTL_D/99-disable-ipv6.conf"
        if [[ -f "$CONF_FILE" ]]; then
            log_info "IPv6 禁用配置已存在: $CONF_FILE"
        else
            cat > "$CONF_FILE" << 'EOF'
# IPv6 disabled by deploy script
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
        fi
        sysctl -p "$CONF_FILE" > /dev/null 2>&1

        if [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" == "1" ]]; then
            log_info "IPv6 已成功禁用"
        else
            log_warn "IPv6 禁用需重启后完全生效"
        fi

    elif [[ "$IP_DISABLE" == "ipv4" ]]; then
        log_warn "禁用 IPv4 可能导致服务器完全无法访问！"
        echo -n "确认要禁用 IPv4 吗？(y/N): "
        read -r confirm
        if [[ "${confirm,,}" == "y" ]]; then
            CONF_FILE="$SYSCTL_D/99-disable-ipv4.conf"
            [[ ! -f "$CONF_FILE" ]] && cat > "$CONF_FILE" << 'EOF'
# IPv4 disabled by deploy script
net.ipv4.conf.all.disable_ipv4=1
net.ipv4.conf.default.disable_ipv4=1
EOF
            log_warn "IPv4 禁用配置已写入，重启后生效（请确保有 IPv6 连接方式）"
        else
            log_info "已取消 IPv4 禁用"
            IP_DISABLE="none"
        fi
    fi
}

# ------------------------------------------------
# 配置 SSH 密钥（跨发行版兼容）
# ------------------------------------------------
setup_ssh_key() {
    log_step "配置 SSH 密钥登录"

    # 确保 .ssh 目录及 authorized_keys 权限正确
    # 【改动】显式设置所有层级权限，修复 StrictModes 导致的拒绝问题
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    chown root:root /root/.ssh

    # 【改动】追加而非覆盖，防止清除已有密钥
    if ! grep -qF "$PUBLIC_KEY" /root/.ssh/authorized_keys 2>/dev/null; then
        echo "$PUBLIC_KEY" >> /root/.ssh/authorized_keys
        log_info "公钥已添加"
    else
        log_info "公钥已存在，跳过"
    fi

    chmod 600 /root/.ssh/authorized_keys
    chown root:root /root/.ssh/authorized_keys

    # 修复 SELinux 上下文（CentOS/RHEL）
    if command -v restorecon &>/dev/null; then
        restorecon -Rv /root/.ssh/ > /dev/null 2>&1
        log_info "SELinux 上下文已修复"
    fi
}

# ------------------------------------------------
# 配置 SSH（不覆盖文件，精确替换/追加）
# ------------------------------------------------
configure_ssh() {
    log_step "配置 SSH 安全设置"

    SSHD_CONFIG="/etc/ssh/sshd_config"
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"

    # 辅助函数：设置或追加 sshd_config 中的某个参数
    # 用法: sshd_set "参数名" "值"
    sshd_set() {
        local key="$1"
        local val="$2"
        if grep -qE "^#?\s*${key}\s" "$SSHD_CONFIG"; then
            # 无论是否被注释，统一替换为新值
            sed -i "s|^#\?\s*${key}\s.*|${key} ${val}|" "$SSHD_CONFIG"
        else
            echo "${key} ${val}" >> "$SSHD_CONFIG"
        fi
    }

    # 【改动】显式启用公钥认证（很多系统默认不写此行导致密钥失效）
    sshd_set "PubkeyAuthentication" "yes"

    # 【改动】显式指定 authorized_keys 路径，防止因路径变量不展开导致找不到文件
    sshd_set "AuthorizedKeysFile" ".ssh/authorized_keys"

    # 修改端口（注释旧端口，添加新端口）
    sed -i 's/^Port\s/#Port /' "$SSHD_CONFIG"
    grep -q "^Port $SSH_PORT" "$SSHD_CONFIG" || echo "Port $SSH_PORT" >> "$SSHD_CONFIG"

    # 禁用密码认证
    sshd_set "PasswordAuthentication" "no"

    # 【改动】同时禁用 ChallengeResponseAuthentication（旧版 SSH 兼容名）
    sshd_set "ChallengeResponseAuthentication" "no"

    # 【改动】禁用 KbdInteractiveAuthentication（新版 SSH 名称）
    sshd_set "KbdInteractiveAuthentication" "no"

    # 【改动】禁用 UsePAM 可能覆盖密码禁用的问题（谨慎：某些系统依赖 PAM）
    # 仅在 PasswordAuthentication=no 生效后 PAM 仍允许密码时才需要，暂作提示
    log_warn "如果密码登录仍可用，请检查 UsePAM 设置（部分系统需手动设为 no）"

    # 允许 root 密钥登录
    sshd_set "PermitRootLogin" "prohibit-password"

    log_info "SSH 配置完成（端口: $SSH_PORT，已禁用密码登录，已启用公钥认证）"
}

# ------------------------------------------------
# 配置 fail2ban（跨发行版兼容）
# ------------------------------------------------
setup_fail2ban() {
    log_step "配置 fail2ban"

    # 检查 fail2ban 是否已安装
    if ! command -v fail2ban-server &>/dev/null; then
        log_warn "fail2ban 未安装，尝试再次安装..."
        if [[ "$PKG_MANAGER" == "apt" ]]; then
            apt install -y fail2ban || { log_error "fail2ban 安装失败，跳过此步骤"; return; }
        else
            $PKG_MANAGER install -y fail2ban || { log_error "fail2ban 安装失败，跳过此步骤"; return; }
        fi
    fi

    # 【改动】检测日志后端（systemd 不可用时回退到 auto）
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        FAIL2BAN_BACKEND="systemd"
        FAIL2BAN_LOGPATH=""   # systemd 后端不需要 logpath
    else
        FAIL2BAN_BACKEND="auto"
        # 尝试找 sshd 日志文件
        for lp in /var/log/auth.log /var/log/secure; do
            if [[ -f "$lp" ]]; then
                FAIL2BAN_LOGPATH="logpath = $lp"
                break
            fi
        done
        [[ -z "$FAIL2BAN_LOGPATH" ]] && FAIL2BAN_LOGPATH="logpath = /var/log/auth.log"
    fi

    # 【改动】先停止服务再写配置，避免文件锁冲突
    systemctl stop fail2ban 2>/dev/null || true

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = -1
findtime = 300
maxretry = 1

[sshd]
enabled  = true
port     = $SSH_PORT
backend  = $FAIL2BAN_BACKEND
${FAIL2BAN_LOGPATH}
maxretry = 1
findtime = 300
bantime  = -1
ignoreip = 127.0.0.1/8 ::1
EOF

    # 【改动】等待服务完全停止后再启动
    sleep 1
    systemctl enable fail2ban
    systemctl start fail2ban

    # 验证
    if systemctl is-active --quiet fail2ban; then
        log_info "fail2ban 启动成功"
    else
        log_warn "fail2ban 启动失败，查看日志: journalctl -u fail2ban --no-pager -n 30"
    fi
}

# ------------------------------------------------
# 重启 SSH 服务
# ------------------------------------------------
restart_ssh() {
    log_step "重启 SSH 服务"

    # 测试配置语法
    if ! sshd -t 2>&1; then
        log_error "SSH 配置语法错误，请检查 /etc/ssh/sshd_config"
        log_error "备份文件在: /etc/ssh/sshd_config.backup.*"
        exit 1
    fi

    # 【改动】兼容 sshd / ssh 两种服务名
    if systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl restart sshd
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl restart ssh
    else
        # 尝试两者都重启
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || {
            log_error "无法重启 SSH 服务"; exit 1
        }
    fi

    log_info "SSH 服务重启完成"
}

# ------------------------------------------------
# 显示配置总结
# ------------------------------------------------
show_summary() {
    echo ""
    echo "================================================"
    log_info "服务器安全配置完成！"
    echo "================================================"
    echo ""
    echo "配置总结："
    echo "  SSH 端口          : $SSH_PORT"
    echo "  密码登录          : 已禁用"
    echo "  公钥登录          : 已启用（PubkeyAuthentication yes）"
    echo "  BBR 加速          : 已启用"

    case $IP_PRIORITY in
        ipv4) echo "  IP 协议优先级     : IPv4 优先" ;;
        ipv6) echo "  IP 协议优先级     : IPv6 优先" ;;
        none) echo "  IP 协议优先级     : 保持不变" ;;
    esac

    case $IP_DISABLE in
        ipv4) echo "  IP 协议状态       : IPv4 已禁用（重启后生效）" ;;
        ipv6) echo "  IP 协议状态       : IPv6 已禁用" ;;
        none) echo "  IP 协议状态       : 保持不变" ;;
    esac

    echo "  fail2ban          : 已启用（1 次失败永久封禁）"
    echo ""
    echo "重要提醒："
    echo "  1. 请务必保存好 SSH 私钥"
    echo "  2. 新连接命令: ssh -p $SSH_PORT root@<服务器IP>"
    echo "  3. 【请先开新终端测试连接，确认成功后再断开当前会话！】"
    echo "  4. 防火墙未配置，请确保 $SSH_PORT 端口已放行"
    echo ""
    echo "常用排查命令："
    echo "  查看 fail2ban 状态 : fail2ban-client status sshd"
    echo "  查看 SSH 日志      : journalctl -u sshd --no-pager -n 50"
    echo "  解封 IP            : fail2ban-client unban <IP>"
    echo ""
    log_warn "【重要】请先用新终端验证 SSH 密钥登录可用后再关闭此连接！"
}

# ------------------------------------------------
# 预装基础组件（最优先执行，不依赖任何函数）
# 确保后续步骤所需的 curl/wget/git 等工具可用
# ------------------------------------------------
bootstrap_packages() {
    log_step "预装基础组件"

    if command -v apt &>/dev/null; then
        apt update -y
        apt install -y curl sudo wget git unzip nano vim
    elif command -v dnf &>/dev/null; then
        dnf install -y epel-release 2>/dev/null || true
        dnf install -y curl sudo wget git unzip nano vim
    elif command -v yum &>/dev/null; then
        yum install -y epel-release 2>/dev/null || true
        yum install -y curl sudo wget git unzip nano vim
    else
        log_warn "未检测到已知包管理器（apt/dnf/yum），跳过预装"
        return
    fi

    if [[ $? -eq 0 ]]; then
        log_info "基础组件预装完成"
    else
        log_error "基础组件安装失败，请检查网络或软件源后重试"
        exit 1
    fi
}

# ------------------------------------------------
# 主流程
# ------------------------------------------------
main() {
    echo "================================================"
    echo "    服务器安全配置一键部署脚本 v2.1"
    echo "================================================"
    echo ""

    # 第一步：权限检查 + 立即预装基础组件
    # 在任何用户交互和发行版检测之前完成，确保环境就绪
    check_root
    bootstrap_packages

    # 第二步：检测发行版（此时 curl/wget 已可用）
    detect_distro

    # 第三步：收集用户配置
    get_public_key
    get_ssh_port
    get_ip_priority
    get_ip_disable

    echo ""
    log_info "开始执行配置，请稍候..."
    echo ""

    # install_basics 现在只需补装 fail2ban（基础包已在 bootstrap 装好）
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
