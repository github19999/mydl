#!/bin/bash

# Fail2ban 完全修复脚本
# 解决各种fail2ban启动问题

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

echo "========================================"
echo "      Fail2ban 完全修复脚本"
echo "========================================"
echo ""

# 1. 完全停止fail2ban服务
log_step "完全停止fail2ban服务"
systemctl stop fail2ban 2>/dev/null || true
pkill -f fail2ban-server 2>/dev/null || true
pkill -f fail2ban 2>/dev/null || true
sleep 2
log_info "服务已停止"

# 2. 清理所有残留文件和目录
log_step "清理残留文件"
rm -rf /var/run/fail2ban/* 2>/dev/null || true
rm -rf /run/fail2ban/* 2>/dev/null || true
rm -f /var/run/fail2ban.pid 2>/dev/null || true
rm -f /run/fail2ban.pid 2>/dev/null || true
rm -f /var/log/fail2ban.log 2>/dev/null || true
log_info "残留文件已清理"

# 3. 重新创建目录结构
log_step "重新创建目录结构"
mkdir -p /var/run/fail2ban
mkdir -p /run/fail2ban
chmod 755 /var/run/fail2ban
chmod 755 /run/fail2ban
chown root:root /var/run/fail2ban
chown root:root /run/fail2ban
log_info "目录结构已重建"

# 4. 检查系统日志配置
log_step "检查系统日志配置"
if [[ -f /var/log/auth.log ]]; then
    LOGPATH="/var/log/auth.log"
    log_info "使用日志文件: /var/log/auth.log"
elif [[ -f /var/log/secure ]]; then
    LOGPATH="/var/log/secure" 
    log_info "使用日志文件: /var/log/secure"
else
    # 创建auth.log文件
    touch /var/log/auth.log
    chmod 640 /var/log/auth.log
    chown root:adm /var/log/auth.log 2>/dev/null || chown root:root /var/log/auth.log
    LOGPATH="/var/log/auth.log"
    log_info "创建日志文件: /var/log/auth.log"
fi

# 5. 获取SSH端口
log_step "检测SSH端口"
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -1)
if [[ -z "$SSH_PORT" ]]; then
    SSH_PORT=22
fi
log_info "SSH端口: $SSH_PORT"

# 6. 检测IPv6状态
log_step "检测IPv6状态"
IPV6_DISABLED=false
if [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null) == "1" ]]; then
    IPV6_DISABLED=true
    log_info "IPv6已禁用，使用IPv4专用配置"
else
    log_info "IPv6可用，使用完整配置"
fi

# 7. 完全重新安装fail2ban
log_step "重新安装fail2ban"
apt remove --purge fail2ban -y > /dev/null 2>&1
rm -rf /etc/fail2ban
apt update > /dev/null 2>&1
apt install fail2ban -y
if [[ $? -eq 0 ]]; then
    log_info "fail2ban重新安装完成"
else
    log_error "fail2ban安装失败"
    exit 1
fi

# 8. 创建全新配置
log_step "创建全新配置"
rm -f /etc/fail2ban/jail.local

if $IPV6_DISABLED; then
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = -1
findtime = 300
maxretry = 1
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
filter = sshd
port = $SSH_PORT
logpath = $LOGPATH
maxretry = 1
findtime = 300
bantime = -1
ignoreip = 127.0.0.1/8
EOF
else
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = -1
findtime = 300
maxretry = 1
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
filter = sshd
port = $SSH_PORT
logpath = $LOGPATH
maxretry = 1
findtime = 300
bantime = -1
ignoreip = 127.0.0.1/8 ::1
EOF
fi

log_info "配置文件已创建"

# 9. 创建systemd临时文件配置
log_step "配置systemd临时文件"
cat > /etc/tmpfiles.d/fail2ban-fix.conf << EOF
d /var/run/fail2ban 0755 root root -
d /run/fail2ban 0755 root root -
f /var/run/fail2ban/fail2ban.sock 0600 root root -
f /run/fail2ban/fail2ban.sock 0600 root root -
EOF

systemd-tmpfiles --create /etc/tmpfiles.d/fail2ban-fix.conf 2>/dev/null || true
log_info "systemd配置已更新"

# 10. 手动测试配置
log_step "测试配置语法"
if fail2ban-client -t; then
    log_info "配置语法正确"
else
    log_error "配置语法错误，创建最小配置"
    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT
EOF
fi

# 11. 启动服务并验证
log_step "启动fail2ban服务"
systemctl enable fail2ban

# 多次尝试启动
for i in {1..5}; do
    log_info "启动尝试 $i/5"
    
    # 确保目录存在
    mkdir -p /var/run/fail2ban /run/fail2ban
    chmod 755 /var/run/fail2ban /run/fail2ban
    
    # 启动服务
    if systemctl start fail2ban; then
        sleep 3
        
        # 检查服务状态
        if systemctl is-active --quiet fail2ban; then
            log_info "fail2ban启动成功！"
            break
        else
            log_warn "服务状态检查失败，查看错误..."
            journalctl -u fail2ban --no-pager -n 5
        fi
    else
        log_warn "启动命令失败，查看错误..."
        journalctl -u fail2ban --no-pager -n 5
    fi
    
    # 如果不是最后一次尝试，停止服务准备重试
    if [[ $i -lt 5 ]]; then
        systemctl stop fail2ban 2>/dev/null || true
        pkill -f fail2ban 2>/dev/null || true
        sleep 2
        
        # 创建更简单的配置
        cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
EOF
    fi
done

# 12. 最终验证
log_step "最终验证"
sleep 2

if systemctl is-active --quiet fail2ban; then
    log_info "✓ fail2ban服务运行正常"
    
    # 检查socket文件
    if [[ -S /var/run/fail2ban/fail2ban.sock ]] || [[ -S /run/fail2ban/fail2ban.sock ]]; then
        log_info "✓ Socket文件已创建"
        
        # 测试客户端连接
        if fail2ban-client status > /dev/null 2>&1; then
            log_info "✓ 客户端连接正常"
            
            # 测试SSH jail
            if fail2ban-client status sshd > /dev/null 2>&1; then
                log_info "✓ SSH jail配置正常"
                
                echo ""
                echo "========================================"
                log_info "修复成功！fail2ban已正常运行"
                echo "========================================"
                echo ""
                
                # 显示状态信息
                echo "服务状态:"
                fail2ban-client status
                echo ""
                echo "SSH jail状态:"
                fail2ban-client status sshd
                
            else
                log_warn "SSH jail配置可能有问题"
            fi
        else
            log_warn "客户端连接有问题"
        fi
    else
        log_warn "Socket文件未创建"
    fi
else
    log_error "fail2ban服务仍无法正常运行"
    echo ""
    echo "最后的诊断信息:"
    systemctl status fail2ban --no-pager -l
    echo ""
    echo "最近的日志:"
    journalctl -u fail2ban --no-pager -n 10
fi

echo ""
echo "========================================"
echo "         修复脚本执行完成"
echo "========================================"
