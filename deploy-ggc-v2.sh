#!/bin/bash

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
    
    # 添加BBR配置
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    
    # 应用配置
    sysctl -p
    
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

# 配置SSH密钥登录（优化版）
setup_ssh_key() {
    log_step "配置SSH密钥登录"
    
    # 创建ggcuser用户（如果不存在）
    if ! id "ggcuser" &>/dev/null; then
        useradd -m -s /bin/bash ggcuser
        log_info "已创建ggcuser用户"
    else
        log_info "ggcuser用户已存在"
    fi
    
    # 创建.ssh目录
    mkdir -p /home/ggcuser/.ssh
    chmod 700 /home/ggcuser/.ssh
    chown ggcuser:ggcuser /home/ggcuser/.ssh
    
    # 清空并准备authorized_keys文件
    > /home/ggcuser/.ssh/authorized_keys
    chmod 600 /home/ggcuser/.ssh/authorized_keys
    chown ggcuser:ggcuser /home/ggcuser/.ssh/authorized_keys
    
    log_info "已创建并清空 /home/ggcuser/.ssh/authorized_keys 文件"
    echo ""
    log_warn "现在将打开nano编辑器，请按以下步骤操作："
    echo "1. 在编辑器中输入您的SSH公钥（通常以ssh-rsa或ssh-ed25519开头）"
    echo "2. 输入完成后，按 Ctrl+X 保存退出"
    echo "3. 再按 Y 确认保存"
    echo "4. 直接按回车键确认文件名"
    echo ""
    echo -n "准备好后按回车键打开nano编辑器..."
    read
    
    # 打开nano编辑器
    nano /home/ggcuser/.ssh/authorized_keys
    
    # 检查文件是否为空
    if [[ ! -s /home/ggcuser/.ssh/authorized_keys ]]; then
        log_error "未检测到公钥内容，请重新运行脚本"
        exit 1
    fi
    
    log_info "SSH密钥配置完成"
    
    # 同时为root用户设置相同的密钥
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    cp /home/ggcuser/.ssh/authorized_keys /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    chown root:root /root/.ssh/authorized_keys
    
    log_info "已同时为root用户配置SSH密钥"
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

# 配置fail2ban
setup_fail2ban() {
    log_step "配置fail2ban"
    
    # 创建jail.local配置
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
port = $SSH_PORT
logpath = %(sshd_log)s
backend = systemd
maxretry = 1
findtime = 300
bantime = -1
ignoreip = 127.0.0.1/8 ::1
EOF
    
    # 启用并启动fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_info "fail2ban配置完成"
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
    echo "- 密钥登录: 已启用（ggcuser和root用户）"
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
    
    echo "- fail2ban: 已启用（1次失败永久封禁）"
    echo ""
    echo "重要提醒："
    echo "1. 请务必保存好你的SSH私钥"
    echo "2. 新的SSH连接命令:"
    echo "   ssh -p $SSH_PORT ggcuser@你的服务器IP"
    echo "   ssh -p $SSH_PORT root@你的服务器IP"
    echo "3. 如果连接失败，请通过控制台登录检查配置"
    echo "4. 防火墙未进行配置，请根据需要手动设置"
    
    if [[ "$IP_DISABLE" == "ipv4" ]] || [[ "$IP_DISABLE" == "ipv6" ]]; then
        echo "5. IP协议禁用配置可能需要重启系统后完全生效"
    fi
    
    echo ""
    echo "fail2ban状态检查命令："
    echo "sudo fail2ban-client status sshd"
    echo ""
    log_warn "请现在就测试SSH连接，确保能正常登录后再断开当前连接！"
}

# 主函数
main() {
    echo "================================================"
    echo "        服务器安全配置一键部署脚本 v1.4"
    echo "================================================"
    echo ""
    
    # 检查root权限
    check_root
    
    # 获取用户输入
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
