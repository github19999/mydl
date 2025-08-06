#!/bin/bash

#密钥登录   禁止密码登录(不重写文件)   改变端口   BBR   fail2ban安装启用   在deploy-cg-v4.sh基础上增加IPv4/IPv6优先级配置;IPv4/IPv6禁用配置
# v1.5 - 增强版fail2ban修复功能

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 获取用户输入的公钥
get_public_key() {
    echo ""
    log_step "配置SSH密钥登录"
    echo "请输入你的SSH公钥（通常以ssh-rsa开头）:"
    read -r PUBLIC_KEY
    
    if [[ -z "$PUBLIC_KEY" ]]; then
        log_error "公钥不能为空"
        exit 1
    fi
    
    if [[ ! "$PUBLIC_KEY" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
        log_warn "公钥格式可能不正确，但继续执行..."
    fi
}

# 获取新的SSH端口
get_ssh_port() {
    echo ""
    log_step "配置SSH端口"
    echo "请输入新的SSH端口（建议10000-65535之间，默认43916）:"
    read -r SSH_PORT
    
    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT=43916
    fi
    
    # 验证端口范围
    if [[ $SSH_PORT -lt 1024 || $SSH_PORT -gt 65535 ]]; then
        log_error "端口范围应在1024-65535之间"
        exit 1
    fi
    
    log_info "将使用SSH端口: $SSH_PORT"
}

# 获取IP协议优先级配置
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
        1)
            IP_PRIORITY="ipv4"
            log_info "将设置IPv4优先"
            ;;
        2)
            IP_PRIORITY="ipv6"
            log_info "将设置IPv6优先"
            ;;
        3)
            IP_PRIORITY="none"
            log_info "将保持IP协议优先级不变"
            ;;
        *)
            log_warn "无效选择，使用默认设置（IPv4优先）"
            IP_PRIORITY="ipv4"
            ;;
    esac
}

# 获取IP协议禁用配置
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
        1)
            IP_DISABLE="ipv6"
            log_info "将禁用IPv6"
            ;;
        2)
            IP_DISABLE="ipv4"
            log_info "将禁用IPv4"
            ;;
        3)
            IP_DISABLE="none"
            log_info "将保持IP协议状态不变"
            ;;
        *)
            log_warn "无效选择，使用默认设置（禁用IPv6）"
            IP_DISABLE="ipv6"
            ;;
    esac
}

# 系统更新和基础软件安装
install_basics() {
    log_step "更新系统并安装基础软件"
    
    apt update -y
    apt install -y curl sudo wget git unzip nano vim fail2ban
    
    if [[ $? -eq 0 ]]; then
        log_info "基础软件安装完成"
    else
        log_error "基础软件安装失败"
        exit 1
    fi
}

# 启用BBR加速
enable_bbr() {
    log_step "启用BBR拥塞控制算法"
    
    # 检查是否已经启用BBR
    current_congestion=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d= -f2 | tr -d ' ')
    
    if [[ "$current_congestion" == "bbr" ]]; then
        log_info "BBR已经启用"
        return
    fi
    
    # 检查是否已有BBR配置，避免重复添加
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    
    if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    
    # 应用配置
    sysctl -p > /dev/null 2>&1
    
    # 验证BBR是否启用成功
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        log_info "BBR启用成功"
    else
        log_warn "BBR启用可能失败，请检查内核版本"
    fi
}

# 设置IP协议优先级
set_ip_priority() {
    if [[ "$IP_PRIORITY" == "none" ]]; then
        log_info "跳过IP协议优先级设置"
        return
    fi
    
    log_step "设置IP协议优先级"
    
    # 检查gai.conf文件是否存在
    if [[ ! -f /etc/gai.conf ]]; then
        log_warn "/etc/gai.conf文件不存在，跳过IP协议优先级设置"
        return
    fi
    
    # 备份原配置文件
    cp /etc/gai.conf /etc/gai.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    if [[ "$IP_PRIORITY" == "ipv4" ]]; then
        # 设置IPv4优先
        if grep -q "^#precedence ::ffff:0:0/96" /etc/gai.conf; then
            # 取消注释
            sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf
            log_info "已启用IPv4优先设置"
        elif grep -q "^precedence ::ffff:0:0/96" /etc/gai.conf; then
            log_info "IPv4优先设置已经启用"
        else
            # 如果没有找到相关配置，手动添加
            echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
            log_info "已添加IPv4优先设置"
        fi
    elif [[ "$IP_PRIORITY" == "ipv6" ]]; then
        # 设置IPv6优先（注释掉IPv4优先设置）
        if grep -q "^precedence ::ffff:0:0/96" /etc/gai.conf; then
            # 注释掉IPv4优先设置
            sed -i 's/^precedence ::ffff:0:0\/96  100/#precedence ::ffff:0:0\/96  100/' /etc/gai.conf
            log_info "已设置IPv6优先（注释IPv4优先配置）"
        else
            log_info "IPv6优先设置已经生效（未找到IPv4优先配置）"
        fi
    fi
}

# 禁用指定的IP协议
disable_ip_protocol() {
    if [[ "$IP_DISABLE" == "none" ]]; then
        log_info "跳过IP协议禁用设置"
        return
    fi
    
    log_step "禁用IP协议"
    
    # 备份原配置文件
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    if [[ "$IP_DISABLE" == "ipv6" ]]; then
        # 禁用IPv6
        if grep -q "net.ipv6.conf.all.disable_ipv6=1" /etc/sysctl.conf; then
            log_info "IPv6禁用配置已存在"
            return
        fi
        
        # 添加IPv6禁用配置
        cat >> /etc/sysctl.conf << EOF

# IPv6 disabled
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
        
        # 应用配置
        sysctl -p > /dev/null 2>&1
        
        # 验证IPv6是否已禁用
        if [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null) == "1" ]]; then
            log_info "IPv6已成功禁用"
        else
            log_warn "IPv6禁用可能需要重启系统后生效"
        fi
        
    elif [[ "$IP_DISABLE" == "ipv4" ]]; then
        # 禁用IPv4（这是一个危险操作，需要特别小心）
        log_warn "禁用IPv4是一个危险操作，可能导致系统无法访问"
        echo -n "确定要禁用IPv4吗？(y/N): "
        read -r confirm
        
        if [[ "$confirm" == "y" ]] || [[ "$confirm" == "Y" ]]; then
            # 检查是否已经存在IPv4禁用配置
            if grep -q "net.ipv4.conf.all.disable_ipv4=1" /etc/sysctl.conf; then
                log_info "IPv4禁用配置已存在"
                return
            fi
            
            # 添加IPv4禁用配置
            cat >> /etc/sysctl.conf << EOF

# IPv4 disabled
net.ipv4.conf.all.disable_ipv4=1
net.ipv4.conf.default.disable_ipv4=1
EOF
            
            log_warn "IPv4禁用配置已添加，重启后生效（请确保有IPv6连接方式）"
        else
            log_info "已取消IPv4禁用操作"
            IP_DISABLE="none"
        fi
    fi
}

# 配置SSH密钥登录
setup_ssh_key() {
    log_step "配置SSH密钥登录"
    
    # 创建.ssh目录
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    # 添加公钥
    echo "$PUBLIC_KEY" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    chown root:root /root/.ssh/authorized_keys
    
    log_info "SSH密钥配置完成"
}

# 配置SSH安全设置
configure_ssh() {
    log_step "配置SSH安全设置"
    
    # 备份原配置文件
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
    
    # 修改SSH端口
    if grep -q "^Port 22" /etc/ssh/sshd_config; then
        # 如果存在未注释的Port 22，则注释掉
        sed -i 's/^Port 22/#Port 22/' /etc/ssh/sshd_config
        log_info "已注释原Port 22配置"
    fi
    
    # 检查是否已存在新端口配置
    if ! grep -q "^Port $SSH_PORT" /etc/ssh/sshd_config; then
        # 添加新端口配置
        echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
        log_info "已添加新端口配置: $SSH_PORT"
    else
        log_info "端口 $SSH_PORT 已存在于配置中"
    fi
    
    # 禁用密码认证
    if grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    else
        echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    fi
    
    log_info "SSH配置完成，端口: $SSH_PORT，已禁用密码登录"
}

# 智能修复fail2ban运行环境
fix_fail2ban_environment() {
    log_step "检查并修复fail2ban运行环境"
    
    # 先检查fail2ban是否已经正常运行
    if systemctl is-active --quiet fail2ban && fail2ban-client status >/dev/null 2>&1; then
        log_info "fail2ban已正常运行，跳过修复"
        return 0
    fi
    
    log_warn "检测到fail2ban运行异常，开始智能修复..."
    
    # 停止fail2ban服务
    systemctl stop fail2ban 2>/dev/null || true
    pkill -9 -f fail2ban 2>/dev/null || true
    sleep 2
    
    # 检查并创建必要的运行时目录
    local directories=(
        "/var/run/fail2ban"
        "/run/fail2ban"
    )
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chown root:root "$dir"
            chmod 755 "$dir"
            log_info "创建目录: $dir"
        else
            # 清理目录中的残留文件
            rm -f "$dir"/* 2>/dev/null || true
        fi
    done
    
    # 创建或更新tmpfiles配置
    cat > /etc/tmpfiles.d/fail2ban-fix.conf << 'EOF'
d /var/run/fail2ban 0755 root root -
d /run/fail2ban 0755 root root -
EOF
    
    # 执行tmpfiles配置
    systemd-tmpfiles --create /etc/tmpfiles.d/fail2ban-fix.conf 2>/dev/null || true
    
    # 尝试轻量级修复
    log_info "尝试启动fail2ban服务..."
    if systemctl start fail2ban; then
        sleep 3
        if fail2ban-client status >/dev/null 2>&1; then
            log_info "fail2ban修复成功"
            return 0
        fi
    fi
    
    # 轻量级修复失败，尝试重新安装
    log_warn "轻量级修复失败，进行完全重新安装..."
    
    # 完全停止服务
    systemctl stop fail2ban 2>/dev/null || true
    pkill -9 -f fail2ban 2>/dev/null || true
    
    # 备份用户可能的自定义配置
    if [[ -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.local /tmp/jail.local.backup 2>/dev/null || true
    fi
    
    # 完全卸载
    apt remove --purge fail2ban -y >/dev/null 2>&1
    rm -rf /etc/fail2ban
    rm -rf /var/run/fail2ban
    rm -rf /run/fail2ban
    rm -f /var/log/fail2ban.log
    
    # 重新安装
    apt update >/dev/null 2>&1
    if ! apt install fail2ban -y >/dev/null 2>&1; then
        log_error "fail2ban重新安装失败"
        return 1
    fi
    
    # 重新创建目录
    mkdir -p /var/run/fail2ban /run/fail2ban
    chmod 755 /var/run/fail2ban /run/fail2ban
    chown root:root /var/run/fail2ban /run/fail2ban
    
    log_info "fail2ban重新安装完成"
    return 0
}

# 配置fail2ban
setup_fail2ban() {
    log_step "配置fail2ban"
    
    # 先修复运行环境
    if ! fix_fail2ban_environment; then
        log_error "fail2ban环境修复失败，跳过fail2ban配置"
        return
    fi
    
    # 检测系统环境
    local ipv6_disabled=false
    if [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null) == "1" ]] || [[ "$IP_DISABLE" == "ipv6" ]]; then
        ipv6_disabled=true
        log_info "检测到IPv6已禁用，使用IPv4专用配置"
    fi
    
    # 检测日志文件路径
    local logpath="/var/log/auth.log"
    if [[ ! -f "/var/log/auth.log" ]]; then
        if [[ -f "/var/log/secure" ]]; then
            logpath="/var/log/secure"
        else
            # 创建auth.log文件
            touch /var/log/auth.log
            chmod 640 /var/log/auth.log
            chown root:adm /var/log/auth.log 2>/dev/null || chown root:root /var/log/auth.log
            logpath="/var/log/auth.log"
        fi
    fi
    log_info "使用日志文件: $logpath"
    
    # 创建jail.local配置
    if $ipv6_disabled; then
        # IPv6禁用环境的配置
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 忽略的IP地址（仅IPv4）
ignoreip = 127.0.0.1/8

# 默认禁止时间（-1表示永久）
bantime = -1

# 检测时间窗口（秒）
findtime = 300

# 最大重试次数
maxretry = 1

[sshd]
enabled = true
filter = sshd
port = $SSH_PORT
logpath = $logpath
backend = systemd
maxretry = 1
findtime = 300
bantime = -1
ignoreip = 127.0.0.1/8
EOF
    else
        # 标准配置（支持IPv4和IPv6）
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 忽略的IP地址
ignoreip = 127.0.0.1/8 ::1

# 默认禁止时间（-1表示永久）
bantime = -1

# 检测时间窗口（秒）
findtime = 300

# 最大重试次数
maxretry = 1

[sshd]
enabled = true
filter = sshd
port = $SSH_PORT
logpath = $logpath
backend = systemd
maxretry = 1
findtime = 300
bantime = -1
ignoreip = 127.0.0.1/8 ::1
EOF
    fi
    
    # 测试配置语法
    if ! fail2ban-client -t; then
        log_warn "配置语法检查失败，使用最简配置"
        cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 1
bantime = -1
EOF
    fi
    
    # 启用并启动fail2ban
    systemctl enable fail2ban
    
    # 多次尝试启动，渐进式降低配置复杂度
    local max_attempts=5
    local attempt=1
    local success=false
    
    while [[ $attempt -le $max_attempts ]] && [[ $success == false ]]; do
        log_info "尝试启动fail2ban (第${attempt}次)"
        
        # 确保目录存在
        mkdir -p /var/run/fail2ban /run/fail2ban
        chmod 755 /var/run/fail2ban /run/fail2ban
        
        if systemctl start fail2ban; then
            sleep 3
            if systemctl is-active --quiet fail2ban && fail2ban-client status >/dev/null 2>&1; then
                log_info "fail2ban启动成功"
                success=true
                break
            fi
        fi
        
        log_warn "启动失败，尝试简化配置..."
        
        # 停止服务准备重试
        systemctl stop fail2ban 2>/dev/null || true
        pkill -f fail2ban 2>/dev/null || true
        sleep 1
        
        # 根据尝试次数逐步简化配置
        case $attempt in
            2)
                # 简化配置 - 移除backend
                if $ipv6_disabled; then
                    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime = -1
findtime = 300
maxretry = 1

[sshd]
enabled = true
filter = sshd
port = $SSH_PORT
logpath = $logpath
maxretry = 1
bantime = -1
EOF
                else
                    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = -1
findtime = 300
maxretry = 1

[sshd]
enabled = true
filter = sshd
port = $SSH_PORT
logpath = $logpath
maxretry = 1
bantime = -1
EOF
                fi
                ;;
            3)
                # 更简化的配置
                cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
filter = sshd
port = $SSH_PORT
logpath = $logpath
maxretry = 1
bantime = -1
EOF
                ;;
            4)
                # 最简配置 - 使用默认日志
                cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 1
bantime = -1
EOF
                ;;
            5)
                # 最基础配置
                cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
EOF
                ;;
        esac
        
        ((attempt++))
    done
    
    # 最终状态检查和报告
    if $success; then
        log_info "fail2ban配置完成并运行正常"
        
        # 显示配置状态
        if fail2ban-client status sshd >/dev/null 2>&1; then
            log_info "SSH jail配置成功"
        else
            log_warn "SSH jail可能未正确配置，但服务运行正常"
        fi
    else
        log_error "fail2ban启动失败，但不影响其他安全配置"
        log_warn "可能需要手动检查系统环境或稍后重试"
        
        # 提供手动修复建议
        echo ""
        echo "手动修复建议："
        echo "1. 检查系统日志: journalctl -u fail2ban -n 20"
        echo "2. 检查配置语法: fail2ban-client -t"
        echo "3. 手动启动: systemctl start fail2ban"
        echo "4. 重新运行脚本或联系支持"
    fi
}

# 重启SSH服务
restart_ssh() {
    log_step "重启SSH服务"
    
    # 测试SSH配置
    if sshd -t; then
        systemctl restart sshd
        log_info "SSH服务重启完成"
    else
        log_error "SSH配置测试失败，请检查配置"
        exit 1
    fi
}

# 显示配置总结
show_summary() {
    echo ""
    echo "================================================"
    log_info "服务器安全配置完成！"
    echo "================================================"
    echo ""
    echo "配置总结："
    echo "- SSH端口: $SSH_PORT"
    echo "- 密码登录: 已禁用"
    echo "- 密钥登录: 已启用"
    echo "- BBR加速: 已启用"
    
    # 显示IP协议配置
    case $IP_PRIORITY in
        "ipv4")
            echo "- IP协议优先级: IPv4优先"
            ;;
        "ipv6")
            echo "- IP协议优先级: IPv6优先"
            ;;
        "none")
            echo "- IP协议优先级: 保持不变"
            ;;
    esac
    
    case $IP_DISABLE in
        "ipv4")
            echo "- IP协议状态: IPv4已禁用"
            ;;
        "ipv6")
            echo "- IP协议状态: IPv6已禁用"
            ;;
        "none")
            echo "- IP协议状态: 保持不变"
            ;;
    esac
    
    # 检查fail2ban状态
    if systemctl is-active --quiet fail2ban; then
        if fail2ban-client status >/dev/null 2>&1; then
            echo "- fail2ban: ✓ 已启用并运行正常（1次失败永久封禁）"
            
            # 显示详细状态
            if fail2ban-client status sshd >/dev/null 2>&1; then
                echo "  └── SSH保护: ✓ 已启用"
            else
                echo "  └── SSH保护: ⚠ 基础配置"
            fi
        else
            echo "- fail2ban: ⚠ 服务运行但客户端连接异常"
        fi
    else
        echo "- fail2ban: ✗ 未成功启动（可手动修复）"
    fi
    
    echo ""
    echo "重要提醒："
    echo "1. 请务必保存好你的SSH私钥"
    echo "2. 新的SSH连接命令: ssh -p $SSH_PORT root@你的服务器IP"
    echo "3. 如果连接失败，请通过控制台登录检查配置"
    echo "4. 防火墙未进行配置，请根据需要手动设置"
    
    if [[ "$IP_DISABLE" == "ipv4" ]] || [[ "$IP_DISABLE" == "ipv6" ]]; then
        echo "5. IP协议禁用配置可能需要重启系统后完全生效"
    fi
    
    echo ""
    echo "fail2ban管理命令："
    echo "- 查看状态: sudo fail2ban-client status"
    echo "- 查看SSH保护: sudo fail2ban-client status sshd"
    echo "- 查看封禁列表: sudo fail2ban-client status sshd | grep 'Banned IP'"
    echo "- 解封IP: sudo fail2ban-client set sshd unbanip [IP地址]"
    
    echo ""
    log_warn "请现在就测试SSH连接，确保能正常登录后再断开当前连接！"
    
    # 额外的状态检查信息
    echo ""
    echo "当前系统状态："
    echo "- 系统版本: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 2>/dev/null || echo '未知')"
    echo "- 内核版本: $(uname -r)"
    echo "- SSH服务: $(systemctl is-active sshd)"
    echo "- Fail2ban服务: $(systemctl is-active fail2ban 2>/dev/null || echo 'inactive')"
}

# 主函数
main() {
    echo "================================================"
    echo "        服务器安全配置一键部署脚本 v1.5"
    echo "       (增强版 - 智能fail2ban修复)"
    echo "================================================"
    echo ""
    
    # 检查root权限
    check_root
    
    # 获取用户输入
    get_public_key
    get_ssh_port
    get_ip_priority
    get_ip_disable
    
    echo ""
    log_info "开始执行配置，请稍候..."
    echo ""
    
    # 执行配置步骤
    install_basics
    enable_bbr
    set_ip_priority
    disable_ip_protocol
    setup_ssh_key
    configure_ssh
    setup_fail2ban
    restart_ssh
    
    # 显示配置总结
    show_summary
}

# 执行主函数
main "$@"
