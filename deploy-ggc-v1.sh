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

# 切换到root用户
switch_to_root() {
    if [[ $EUID -ne 0 ]]; then
        log_step "切换到root用户"
        log_info "正在执行 sudo -i，请输入当前用户密码"
        exec sudo -i bash "$0" "$@"
    fi
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

# 系统更新和基础软件安装
install_basics() {
    log_step "更新系统并安装基础软件"
    
    apt update -y
    apt install -y curl sudo wget git unzip nano vim ufw fail2ban
    
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

# 配置SSH密钥登录
setup_ssh_key() {
    log_step "配置SSH密钥登录"
    
    # 确定当前用户名（从环境变量或默认为ggcuser）
    if [[ -n "$SUDO_USER" ]]; then
        CURRENT_USER="$SUDO_USER"
    else
        CURRENT_USER="ggcuser"
    fi
    
    # 创建用户的.ssh目录
    mkdir -p "/home/$CURRENT_USER/.ssh"
    chmod 700 "/home/$CURRENT_USER/.ssh"
    
    log_info "现在将为用户 $CURRENT_USER 配置SSH密钥"
    log_info "即将打开 nano 编辑器，请按以下步骤操作："
    echo "1. 清空文件中的所有内容"
    echo "2. 粘贴您的SSH公钥（通常以ssh-rsa、ssh-ed25519等开头）"
    echo "3. 按 Ctrl+X 保存并退出"
    echo "4. 按 Y 确认保存"
    echo "5. 直接按回车键退出"
    echo ""
    
    read -p "准备好后请按回车键继续..." -r
    
    # 使用nano编辑authorized_keys文件
    nano "/home/$CURRENT_USER/.ssh/authorized_keys"
    
    # 设置正确的权限和所有者
    chmod 600 "/home/$CURRENT_USER/.ssh/authorized_keys"
    chown "$CURRENT_USER:$CURRENT_USER" "/home/$CURRENT_USER/.ssh/authorized_keys"
    chown "$CURRENT_USER:$CURRENT_USER" "/home/$CURRENT_USER/.ssh"
    
    # 验证公钥是否已添加
    if [[ -s "/home/$CURRENT_USER/.ssh/authorized_keys" ]]; then
        log_info "SSH密钥配置完成"
        log_info "公钥已保存到: /home/$CURRENT_USER/.ssh/authorized_keys"
    else
        log_error "authorized_keys文件为空，请检查是否正确添加了公钥"
        read -p "是否要重新配置密钥？(y/n): " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            setup_ssh_key
        else
            log_warn "跳过密钥配置，但建议稍后手动配置"
        fi
    fi
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

# 配置防火墙
setup_firewall() {
    log_step "配置防火墙"
    
    # 启用ufw
    ufw --force enable
    
    # 允许新的SSH端口
    ufw allow "$SSH_PORT/tcp"
    
    # 设置默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    log_info "防火墙配置完成，已允许SSH端口: $SSH_PORT"
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
    echo "- 密钥登录: 已启用"
    echo "- BBR加速: 已启用"
    echo "- fail2ban: 已启用（1次失败永久封禁）"
    echo "- 防火墙: 已启用"
    echo ""
    echo "重要提醒："
    echo "1. 请务必保存好你的SSH私钥"
    if [[ -n "$SUDO_USER" ]]; then
        echo "2. 新的SSH连接命令: ssh -p $SSH_PORT $SUDO_USER@你的服务器IP"
    else
        echo "2. 新的SSH连接命令: ssh -p $SSH_PORT ggcuser@你的服务器IP"
    fi
    echo "3. 如果连接失败，请通过控制台登录检查配置"
    echo ""
    echo "状态检查命令："
    echo "- fail2ban状态: sudo fail2ban-client status sshd"
    echo "- 防火墙状态: ufw status"
    echo "- SSH配置测试: sshd -t"
    echo ""
    log_warn "请现在就测试SSH连接，确保能正常登录后再断开当前连接！"
}

# 主函数
main() {
    echo "================================================"
    echo "        服务器安全配置一键部署脚本"
    echo "================================================"
    echo ""
    
    # 切换到root用户（如果需要）
    switch_to_root "$@"
    
    # 检查root权限
    check_root
    
    # 获取用户输入
    get_ssh_port
    
    echo ""
    log_info "开始执行配置，请稍候..."
    echo ""
    
    # 执行配置步骤
    install_basics
    enable_bbr
    setup_ssh_key
    configure_ssh
    setup_firewall
    setup_fail2ban
    restart_ssh
    
    # 显示配置总结
    show_summary
}

# 执行主函数
main "$@"
