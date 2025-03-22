#!/bin/bash
#
# Linux安全检查脚本 v1.0
# 功能：全面收集系统信息并检测潜在安全威胁
#

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 输出目录
OUTPUT_DIR="security_scan_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/security_report.log"
JSON_REPORT="$OUTPUT_DIR/security_report.json"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

# 初始化JSON报告
echo "{" > "$JSON_REPORT"
echo '  "scan_time": "'$(date -R)'",' >> "$JSON_REPORT"
echo '  "results": {' >> "$JSON_REPORT"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"
}

section_header() {
    echo -e "\n${BLUE}============== $1 ==============${NC}" | tee -a "$LOG_FILE"
    # 添加到JSON
    echo '    "'$1'": {' >> "$JSON_REPORT"
}

section_footer() {
    # 结束JSON部分
    echo '    },' >> "$JSON_REPORT"
}

add_json_entry() {
    local section="$1"
    local key="$2"
    local value="$3"
    local risk="$4" # 可选: "high", "medium", "low"
    
    # 转义JSON字符串
    value=$(echo "$value" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g')
    
    if [ -n "$risk" ]; then
        echo '      "'$key'": {"value": "'$value'", "risk": "'$risk'"},' >> "$JSON_REPORT"
    else
        echo '      "'$key'": "'$value'",' >> "$JSON_REPORT"
    fi
}

# 检查是否为root用户
check_root() {
    section_header "权限验证"
    if [ "$(id -u)" -eq 0 ]; then
        log_success "脚本正在以root权限运行"
        add_json_entry "权限验证" "root_check" "通过" "low"
    else
        log_critical "脚本需要root权限才能完整运行！"
        add_json_entry "权限验证" "root_check" "未通过" "high"
        echo "请使用sudo或root用户运行此脚本。"
        exit 1
    fi
    section_footer
}

# 收集系统基本信息
collect_system_info() {
    section_header "系统基本信息"
    
    # 内核版本
    KERNEL=$(uname -r)
    log_info "内核版本: $KERNEL"
    add_json_entry "系统基本信息" "kernel_version" "$KERNEL"
    
    # 主机名
    HOSTNAME=$(hostname)
    log_info "主机名: $HOSTNAME"
    add_json_entry "系统基本信息" "hostname" "$HOSTNAME"
    
    # IP地址
    IP_INFO=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | tr '\n' ' ')
    log_info "IP地址: $IP_INFO"
    add_json_entry "系统基本信息" "ip_addresses" "$IP_INFO"
    
    # MAC地址
    MAC_INFO=$(ip link | grep -A1 "link/ether" | grep -oP '(?<=link/ether\s)([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | tr '\n' ' ')
    log_info "MAC地址: $MAC_INFO"
    add_json_entry "系统基本信息" "mac_addresses" "$MAC_INFO"
    
    # 网络接口信息
    log_info "网络接口信息:"
    IFACES=$(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')
    add_json_entry "系统基本信息" "network_interfaces" "$IFACES"
    ip -o link show | awk -F': ' '{print "  - " $2}' | tee -a "$LOG_FILE"
    
    # 系统运行级别
    if command -v systemctl &> /dev/null; then
        RUN_LEVEL=$(systemctl get-default)
        log_info "系统运行级别: $RUN_LEVEL"
        add_json_entry "系统基本信息" "run_level" "$RUN_LEVEL"
    else
        RUN_LEVEL=$(runlevel | awk '{print $2}')
        log_info "系统运行级别: $RUN_LEVEL"
        add_json_entry "系统基本信息" "run_level" "$RUN_LEVEL"
    fi
    
    section_footer
}

# 检查用户与账户信息
check_users() {
    section_header "用户与账户信息"
    
    # 列出所有用户
    log_info "系统用户列表:"
    awk -F: '{print "  - " $1 " (UID:" $3 " GID:" $4 ")"}' /etc/passwd | tee -a "$LOG_FILE"
    
    # 查找UID=0的超级用户
    ROOT_USERS=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | tr '\n' ' ')
    if [ "$(echo $ROOT_USERS | wc -w)" -gt 1 ]; then
        log_critical "发现多个具有UID=0的超级用户: $ROOT_USERS"
        add_json_entry "用户与账户信息" "root_users" "$ROOT_USERS" "high"
    else
        log_success "仅有root用户具有UID=0"
        add_json_entry "用户与账户信息" "root_users" "$ROOT_USERS" "low"
    fi
    
    # 检测空口令账户
    EMPTY_PASSWD=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") {print $1}' /etc/shadow | tr '\n' ' ')
    if [ -n "$EMPTY_PASSWD" ]; then
        log_warning "发现空口令账户: $EMPTY_PASSWD"
        add_json_entry "用户与账户信息" "empty_password_accounts" "$EMPTY_PASSWD" "high"
    else
        log_success "未发现空口令账户"
        add_json_entry "用户与账户信息" "empty_password_accounts" "无" "low"
    fi
    
    # 检测最近新增用户
    RECENT_USERS=$(awk -F: '{print $1,$3,$6}' /etc/passwd | sort -n -k2 | tail -5 | awk '{print $1}' | tr '\n' ' ')
    log_info "最近5个UID的用户: $RECENT_USERS"
    add_json_entry "用户与账户信息" "recent_users" "$RECENT_USERS"
    
    # 检查/etc/passwd和/etc/shadow文件权限
    PASSWD_PERM=$(stat -c "%a %U %G" /etc/passwd)
    SHADOW_PERM=$(stat -c "%a %U %G" /etc/shadow)
    
    if [[ "$PASSWD_PERM" == "644 root root" ]]; then
        log_success "/etc/passwd权限正常: $PASSWD_PERM"
        add_json_entry "用户与账户信息" "passwd_permissions" "$PASSWD_PERM" "low"
    else
        log_critical "/etc/passwd权限异常: $PASSWD_PERM (应为644 root root)"
        add_json_entry "用户与账户信息" "passwd_permissions" "$PASSWD_PERM" "high"
    fi
    
    if [[ "$SHADOW_PERM" == "640 root shadow" || "$SHADOW_PERM" == "600 root root" ]]; then
        log_success "/etc/shadow权限正常: $SHADOW_PERM"
        add_json_entry "用户与账户信息" "shadow_permissions" "$SHADOW_PERM" "low"
    else
        log_critical "/etc/shadow权限异常: $SHADOW_PERM (应为640 root shadow或600 root root)"
        add_json_entry "用户与账户信息" "shadow_permissions" "$SHADOW_PERM" "high"
    fi
    
    section_footer
}

# 检查进程与系统资源
check_processes() {
    section_header "进程分析"
    
    # 列出所有运行中的进程
    log_info "获取运行中的进程信息..."
    ps aux > "$OUTPUT_DIR/processes.txt"
    
    # 检查高CPU/内存使用的进程
    HIGH_CPU=$(ps aux | sort -nrk 3,3 | head -5)
    HIGH_MEM=$(ps aux | sort -nrk 4,4 | head -5)
    
    log_info "CPU使用率最高的5个进程:"
    echo "$HIGH_CPU" | awk '{print "  - " $11,$12,$13 " (CPU:" $3"%, MEM:" $4"%)"}' | tee -a "$LOG_FILE"
    
    log_info "内存使用率最高的5个进程:"
    echo "$HIGH_MEM" | awk '{print "  - " $11,$12,$13 " (CPU:" $3"%, MEM:" $4"%)"}' | tee -a "$LOG_FILE"
    
    # 检查可疑进程名称（常见恶意程序）
    SUSPICIOUS_NAMES=("crypto" "miner" "xmrig" "kworker" "coin" "kdevtmpfsi" "kinsing" "kthreaddi" "kswapdi")
    SUSPICIOUS_FOUND=""
    
    for name in "${SUSPICIOUS_NAMES[@]}"; do
        FOUND=$(ps aux | grep -v grep | grep -i "$name" | awk '{print $11,$12}')
        if [ -n "$FOUND" ]; then
            SUSPICIOUS_FOUND+="$name "
            log_warning "发现可疑进程名称: $name - $FOUND"
        fi
    done
    
    if [ -n "$SUSPICIOUS_FOUND" ]; then
        add_json_entry "进程分析" "suspicious_processes" "$SUSPICIOUS_FOUND" "high"
    else
        add_json_entry "进程分析" "suspicious_processes" "无" "low"
    fi
    
    # 使用pstree查看进程树
    if command -v pstree &> /dev/null; then
        log_info "生成进程树..."
        pstree -a > "$OUTPUT_DIR/process_tree.txt"
    fi
    
    # 检查僵尸进程
    ZOMBIES=$(ps aux | awk '{if($8=="Z") print $2,$11,$12}')
    if [ -n "$ZOMBIES" ]; then
        log_warning "发现僵尸进程:"
        echo "$ZOMBIES" | awk '{print "  - PID:" $1 " CMD:" $2}' | tee -a "$LOG_FILE"
        ZOMBIES_COUNT=$(echo "$ZOMBIES" | wc -l)
        add_json_entry "进程分析" "zombie_processes" "$ZOMBIES_COUNT" "medium"
    else
        log_success "未发现僵尸进程"
        add_json_entry "进程分析" "zombie_processes" "0" "low"
    fi
    
    # 检查命名空间隔离的进程
    if command -v lsns &> /dev/null; then
        log_info "检查命名空间隔离的进程..."
        lsns > "$OUTPUT_DIR/namespaces.txt"
        NS_COUNT=$(lsns | wc -l)
        add_json_entry "进程分析" "namespaces_count" "$NS_COUNT"
    fi
    
    section_footer
}

# 检查网络连接
check_network_connections() {
    section_header "网络连接状态"
    
    # 收集所有网络连接
    if command -v ss &> /dev/null; then
        log_info "使用ss命令检查网络连接..."
        ss -tuplan > "$OUTPUT_DIR/network_connections.txt"
        CONN_TOOL="ss"
    elif command -v netstat &> /dev/null; then
        log_info "使用netstat命令检查网络连接..."
        netstat -tuplan > "$OUTPUT_DIR/network_connections.txt"
        CONN_TOOL="netstat"
    else
        log_warning "未找到ss或netstat命令，无法详细检查网络连接"
        CONN_TOOL="none"
    fi
    
    # 检查监听端口
    if [ "$CONN_TOOL" == "ss" ]; then
        LISTENING=$(ss -tuln | grep LISTEN)
    elif [ "$CONN_TOOL" == "netstat" ]; then
        LISTENING=$(netstat -tuln | grep LISTEN)
    fi
    
    if [ -n "$LISTENING" ]; then
        log_info "监听端口列表:"
        echo "$LISTENING" | awk '{print "  - " $5}' | grep -oP ':\d+' | tr -d ':' | sort -n | uniq | \
        while read port; do
            if [ "$CONN_TOOL" == "ss" ]; then
                PROG=$(ss -tulnp | grep ":$port" | awk '{print $7}' | tr -d '\"' | tr -d ',')
            elif [ "$CONN_TOOL" == "netstat" ]; then
                PROG=$(netstat -tulnp | grep ":$port" | awk '{print $7}')
            fi
            echo "  - 端口 $port - 程序: $PROG" | tee -a "$LOG_FILE"
        done
    fi
    
    # 检测非标准高危端口
    SUSPICIOUS_PORTS=("4444" "5555" "3389" "8088" "1080" "31337" "4899" "6666" "6543" "9999")
    SUSPICIOUS_FOUND=""
    
    for port in "${SUSPICIOUS_PORTS[@]}"; do
        if [ "$CONN_TOOL" == "ss" ]; then
            FOUND=$(ss -tuln | grep ":$port ")
        elif [ "$CONN_TOOL" == "netstat" ]; then
            FOUND=$(netstat -tuln | grep ":$port ")
        fi
        
        if [ -n "$FOUND" ]; then
            SUSPICIOUS_FOUND+="$port "
            log_warning "发现可疑端口: $port - $FOUND"
        fi
    done
    
    if [ -n "$SUSPICIOUS_FOUND" ]; then
        add_json_entry "网络连接状态" "suspicious_ports" "$SUSPICIOUS_FOUND" "high"
    else
        add_json_entry "网络连接状态" "suspicious_ports" "无" "low"
    fi
    
    # 检查Established连接
    if [ "$CONN_TOOL" == "ss" ]; then
        ESTABLISHED=$(ss -tun | grep ESTAB)
    elif [ "$CONN_TOOL" == "netstat" ]; then
        ESTABLISHED=$(netstat -tun | grep ESTABLISHED)
    fi
    
    if [ -n "$ESTABLISHED" ]; then
        ESTAB_COUNT=$(echo "$ESTABLISHED" | wc -l)
        log_info "当前已建立的连接数: $ESTAB_COUNT"
        add_json_entry "网络连接状态" "established_connections" "$ESTAB_COUNT"
        
        # 提取远程IP地址
        if [ "$CONN_TOOL" == "ss" ]; then
            REMOTE_IPS=$(echo "$ESTABLISHED" | awk '{print $5}' | cut -d':' -f1 | sort | uniq)
        elif [ "$CONN_TOOL" == "netstat" ]; then
            REMOTE_IPS=$(echo "$ESTABLISHED" | awk '{print $5}' | cut -d':' -f1 | sort | uniq)
        fi
        
        log_info "远程连接IP:"
        echo "$REMOTE_IPS" | awk '{print "  - " $1}' | tee -a "$LOG_FILE"
    fi
    
    section_footer
}

# 检查开放服务
check_services() {
    section_header "开放服务与端口"
    
    # 检查系统服务状态
    if command -v systemctl &> /dev/null; then
        log_info "检查活跃的系统服务..."
        systemctl list-units --type=service --state=running > "$OUTPUT_DIR/running_services.txt"
        SERVICES_COUNT=$(systemctl list-units --type=service --state=running | grep "loaded active running" | wc -l)
        add_json_entry "开放服务与端口" "active_services" "$SERVICES_COUNT"
        
        # 检查常见服务
        COMMON_SERVICES=("ssh" "apache2" "nginx" "httpd" "mysql" "mariadb" "postgresql" "mongodb" "redis" "vsftpd" "smbd" "nfs" "docker" "containerd")
        
        for service in "${COMMON_SERVICES[@]}"; do
            if systemctl is-active --quiet "$service"; then
                log_info "服务 $service 正在运行"
                
                # 获取服务版本
                VERSION=""
                case "$service" in
                    "ssh")
                        VERSION=$(ssh -V 2>&1 | head -1)
                        ;;
                    "apache2"|"httpd")
                        VERSION=$(apache2 -v 2>&1 | head -1 || httpd -v 2>&1 | head -1)
                        ;;
                    "nginx")
                        VERSION=$(nginx -v 2>&1 | head -1)
                        ;;
                    "mysql"|"mariadb")
                        VERSION=$(mysql --version 2>&1 | head -1 || mariadb --version 2>&1 | head -1)
                        ;;
                    "redis")
                        VERSION=$(redis-server --version 2>&1 | head -1)
                        ;;
                    "docker")
                        VERSION=$(docker --version 2>&1 | head -1)
                        ;;
                esac
                
                if [ -n "$VERSION" ]; then
                    log_info "  版本: $VERSION"
                    add_json_entry "开放服务与端口" "${service}_version" "$VERSION"
                fi
            fi
        done
    else
        log_warning "未找到systemctl命令，使用service命令检查..."
        # 对于非systemd系统，使用service命令
        if command -v service &> /dev/null; then
            # 创建服务列表
            service --status-all > "$OUTPUT_DIR/running_services.txt"
        fi
    fi
    
    # 检查高危服务
    HIGH_RISK_SERVICES=("telnet" "rsh" "rlogin" "rexec" "rcmd" "tftp" "rpcbind")
    RISKY_SERVICES=""
    
    for service in "${HIGH_RISK_SERVICES[@]}"; do
        if command -v systemctl &> /dev/null; then
            if systemctl is-active --quiet "$service"; then
                RISKY_SERVICES+="$service "
                log_critical "发现高危服务: $service 正在运行"
            fi
        elif command -v service &> /dev/null; then
            if service "$service" status &>/dev/null; then
                RISKY_SERVICES+="$service "
                log_critical "发现高危服务: $service 正在运行"
            fi
        fi
    done
    
    if [ -n "$RISKY_SERVICES" ]; then
        add_json_entry "开放服务与端口" "high_risk_services" "$RISKY_SERVICES" "high"
    else
        add_json_entry "开放服务与端口" "high_risk_services" "无" "low"
    fi
    
    section_footer
}

# 日志与审计分析
check_logs() {
    section_header "日志分析"
    
    # 创建日志目录
    mkdir -p "$OUTPUT_DIR/logs"
    
    # 定义关键日志文件
    LOG_FILES=("/var/log/auth.log" "/var/log/secure" "/var/log/syslog" "/var/log/messages" "/var/log/audit/audit.log")
    
    # 检查并分析每个日志文件
    for log in "${LOG_FILES[@]}"; do
        if [ -f "$log" ]; then
            log_info "分析日志文件: $log"
            
            # 提取最近100行日志
            tail -n 100 "$log" > "$OUTPUT_DIR/logs/$(basename $log)_recent.txt"
            
            # 检测失败登录
            if [[ "$log" == *"auth.log"* || "$log" == *"secure"* ]]; then
                FAILED_LOGIN=$(grep -i "failed\|failure" "$log" | grep -i "login\|password\|authentication" | tail -n 20)
                
                if [ -n "$FAILED_LOGIN" ]; then
                    FAILED_COUNT=$(echo "$FAILED_LOGIN" | wc -l)
                    log_warning "检测到 $FAILED_COUNT 次失败登录尝试"
                    add_json_entry "日志分析" "failed_logins" "$FAILED_COUNT" "medium"
                    
                    # 提取失败登录的IP地址
                    FAILED_IPS=$(echo "$FAILED_LOGIN" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq)
                    if [ -n "$FAILED_IPS" ]; then
                        log_warning "失败登录的IP地址:"
                        echo "$FAILED_IPS" | awk '{print "  - " $1}' | tee -a "$LOG_FILE"
                    fi
                    
                    # 将详细信息保存到文件
                    echo "$FAILED_LOGIN" > "$OUTPUT_DIR/logs/failed_logins.txt"
                else
                    log_success "未检测到最近的失败登录尝试"
                    add_json_entry "日志分析" "failed_logins" "0" "low"
                fi
                
                # 检测非正常时段登录
                NIGHT_HOURS="00:00:00\|01:00:00\|02:00:00\|03:00:00\|04:00:00\|05:00:00"
                NIGHT_LOGINS=$(grep "session opened" "$log" | grep -E "$NIGHT_HOURS" | tail -n 10)
                
                if [ -n "$NIGHT_LOGINS" ]; then
                    NIGHT_COUNT=$(echo "$NIGHT_LOGINS" | wc -l)
                    log_warning "检测到 $NIGHT_COUNT 次非正常时段(凌晨)登录"
                    add_json_entry "日志分析" "night_logins" "$NIGHT_COUNT" "medium"
                    
                    # 将详细信息保存到文件
                    echo "$NIGHT_LOGINS" > "$OUTPUT_DIR/logs/night_logins.txt"
                else
                    log_success "未检测到非正常时段登录"
                    add_json_entry "日志分析" "night_logins" "0" "low"
                fi
                
                # 检测root直接登录
                ROOT_LOGINS=$(grep "session opened" "$log" | grep "for root" | tail -n 10)
                
                if [ -n "$ROOT_LOGINS" ]; then
                    ROOT_COUNT=$(echo "$ROOT_LOGINS" | wc -l)
                    log_warning "检测到 $ROOT_COUNT 次root用户直接登录"
                    add_json_entry "日志分析" "root_logins" "$ROOT_COUNT" "high"
                    
                    # 将详细信息保存到文件
                    echo "$ROOT_LOGINS" > "$OUTPUT_DIR/logs/root_logins.txt"
                else
                    log_success "未检测到root用户直接登录"
                    add_json_entry "日志分析" "root_logins" "0" "low"
                fi
            fi
            
            # 检测系统错误
            if [[ "$log" == *"syslog"* || "$log" == *"messages"* ]]; then
                SYS_ERRORS=$(grep -i "error\|fail\|critical" "$log" | tail -n 20)
                
                if [ -n "$SYS_ERRORS" ]; then
                    ERROR_COUNT=$(echo "$SYS_ERRORS" | wc -l)
                    log_warning "检测到 $ERROR_COUNT 条系统错误日志"
                    add_json_entry "日志分析" "system_errors" "$ERROR_COUNT" "medium"
                    
                    # 将详细信息保存到文件
                    echo "$SYS_ERRORS" > "$OUTPUT_DIR/logs/system_errors.txt"
                else
                    log_success "未检测到系统错误日志"
                    add_json_entry "日志分析" "system_errors" "0" "low"
                fi
            fi
        else
            log_warning "找不到日志文件: $log"
        fi
    done
    
    section_footer
}

# 检查历史操作记录
check_history() {
    section_header "历史操作记录"
    
    # 获取所有用户的家目录
    USER_HOMES=$(ls -la /home | grep -v "^d.*\." | grep "^d" | awk '{print $9}')
    USER_HOMES="$USER_HOMES root"  # 添加root用户
    
    # 检查每个用户的历史命令
    for user in $USER_HOMES; do
        if [ "$user" == "root" ]; then
            HISTORY_FILE="/root/.bash_history"
        else
            HISTORY_FILE="/home/$user/.bash_history"
        fi
        
        if [ -f "$HISTORY_FILE" ]; then
            log_info "分析用户 $user 的历史命令..."
            
            # 提取敏感命令
            SENSITIVE_CMDS=("wget" "curl" "chmod 777" "rm -rf" "passwd" "useradd" "usermod" "visudo" "chattr" "base64" "python -c" "perl -e" "bash -i" "nc -e" "mkfifo" "ssh-keygen" "ssh-copy-id")
            
            # 创建用户历史记录目录
            mkdir -p "$OUTPUT_DIR/history"
            
            # 复制历史文件
            cp "$HISTORY_FILE" "$OUTPUT_DIR/history/${user}_bash_history.txt"
            
            # 检查敏感命令
            for cmd in "${SENSITIVE_CMDS[@]}"; do
                FOUND=$(grep -i "$cmd" "$HISTORY_FILE")
                if [ -n "$FOUND" ]; then
                    log_warning "用户 $user 使用了敏感命令: $cmd"
                    echo "用户 $user: $FOUND" >> "$OUTPUT_DIR/history/sensitive_commands.txt"
                fi
            done
        else
            log_info "用户 $user 没有历史命令文件"
        fi
    done
    
    # 分析utmp/wtmp登录记录
    if command -v last &> /dev/null; then
        log_info "分析登录记录..."
        
        # 获取最近10次登录
        LAST_LOGINS=$(last -n 10)
        echo "$LAST_LOGINS" > "$OUTPUT_DIR/history/last_logins.txt"
        log_info "最近登录记录:"
        echo "$LAST_LOGINS" | head -10 | awk '{print "  - " $1 " 从 " $3 " 于 " $4, $5, $6, $7}' | tee -a "$LOG_FILE"
        
        # 获取失败登录
        if command -v lastb &> /dev/null; then
            LASTB_LOGINS=$(lastb -n 10)
            echo "$LASTB_LOGINS" > "$OUTPUT_DIR/history/failed_logins.txt"
            LASTB_COUNT=$(echo "$LASTB_LOGINS" | grep -v "^$" | wc -l)
            
            if [ $LASTB_COUNT -gt 0 ]; then
                log_warning "检测到 $LASTB_COUNT 次失败登录尝试"
                add_json_entry "历史操作记录" "failed_login_attempts" "$LASTB_COUNT" "medium"
            else
                log_success "未检测到失败登录尝试"
                add_json_entry "历史操作记录" "failed_login_attempts" "0" "low"
            fi
        fi
    fi
    
    section_footer
}

# 检查审计系统
check_audit() {
    section_header "系统调用审计"
    
    # 检查auditd是否安装并运行
    if command -v auditctl &> /dev/null; then
        if systemctl is-active --quiet auditd; then
            log_success "审计系统(auditd)正在运行"
            add_json_entry "系统调用审计" "auditd_status" "running" "low"
            
            # 获取审计规则
            AUDIT_RULES=$(auditctl -l)
            echo "$AUDIT_RULES" > "$OUTPUT_DIR/audit_rules.txt"
            
            # 检查规则数量
            RULES_COUNT=$(echo "$AUDIT_RULES" | grep -v "No rules" | wc -l)
            log_info "已配置 $RULES_COUNT 条审计规则"
            add_json_entry "系统调用审计" "audit_rules_count" "$RULES_COUNT"
            
            # 分析审计日志
            if [ -f "/var/log/audit/audit.log" ]; then
                log_info "分析审计日志..."
                
                # 检查敏感操作
                SENSITIVE_OPS=$(ausearch -m execve -i 2>/dev/null | grep -i "root" | tail -20 2>/dev/null)
                if [ -n "$SENSITIVE_OPS" ]; then
                    echo "$SENSITIVE_OPS" > "$OUTPUT_DIR/sensitive_audit_events.txt"
                    log_info "已保存最近的敏感审计事件到 sensitive_audit_events.txt"
                fi
            fi
            
            # 为脚本目的添加基本的审计规则建议
            log_info "推荐的基本审计规则:"
            echo "  - 文件系统修改: auditctl -w /etc/passwd -p wa -k identity"
            echo "  - 网络配置修改: auditctl -w /etc/hosts -p wa -k network"
            echo "  - 系统调用监控: auditctl -a always,exit -F arch=b64 -S execve -k exec"
            echo "以上规则可添加到 /etc/audit/rules.d/audit.rules 实现持久化" | tee -a "$LOG_FILE"
        else
            log_warning "审计系统(auditd)已安装但未运行"
            add_json_entry "系统调用审计" "auditd_status" "installed_not_running" "medium"
        fi
    else
        log_warning "审计系统(auditd)未安装"
        add_json_entry "系统调用审计" "auditd_status" "not_installed" "high"
        add_json_entry "系统调用审计" "recommendation" "安装并配置auditd以监控系统调用" "high"
    fi
    
    section_footer
}

# 检查文件系统完整性
check_file_integrity() {
    section_header "文件系统完整性"
    
    # 创建完整性检查目录
    mkdir -p "$OUTPUT_DIR/integrity"
    
    # 检查关键系统文件权限
    log_info "检查关键系统文件权限..."
    
    KEY_BINS=("/bin/su" "/bin/sudo" "/usr/bin/passwd" "/usr/bin/chage" "/usr/bin/gpasswd" "/usr/bin/chsh" "/usr/bin/chfn" "/usr/bin/newgrp")
    
    for bin in "${KEY_BINS[@]}"; do
        if [ -f "$bin" ]; then
            PERM=$(stat -c "%a %U %G" "$bin")
            echo "$bin: $PERM" >> "$OUTPUT_DIR/integrity/key_binaries_perms.txt"
            
            # SUID检查
            if [ $(stat -c "%A" "$bin" | cut -c4) == "s" ]; then
                echo "$bin is SUID" >> "$OUTPUT_DIR/integrity/suid_binaries.txt"
            fi
        fi
    done
    
    # 查找所有SUID/SGID文件
    log_info "搜索SUID/SGID文件..."
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null > "$OUTPUT_DIR/integrity/all_suid_sgid.txt"
    
    SUID_COUNT=$(cat "$OUTPUT_DIR/integrity/all_suid_sgid.txt" | wc -l)
    log_info "找到 $SUID_COUNT 个SUID/SGID文件"
    add_json_entry "文件系统完整性" "suid_sgid_count" "$SUID_COUNT"
    
    # 检查异常SUID文件
    UNUSUAL_SUID=$(grep -v "^/bin\|^/sbin\|^/usr/bin\|^/usr/sbin\|^/usr/libexec" "$OUTPUT_DIR/integrity/all_suid_sgid.txt")
    
    if [ -n "$UNUSUAL_SUID" ]; then
        UNUSUAL_COUNT=$(echo "$UNUSUAL_SUID" | wc -l)
        log_warning "发现 $UNUSUAL_COUNT 个非标准位置的SUID/SGID文件"
        add_json_entry "文件系统完整性" "unusual_suid_sgid" "$UNUSUAL_COUNT" "high"
        
        echo "$UNUSUAL_SUID" > "$OUTPUT_DIR/integrity/unusual_suid_sgid.txt"
        echo "$UNUSUAL_SUID" | head -5 | awk '{print "  - " $9}' | tee -a "$LOG_FILE"
        if [ $UNUSUAL_COUNT -gt 5 ]; then
            echo "  ... 更多内容见报告文件 unusual_suid_sgid.txt" | tee -a "$LOG_FILE"
        fi
    else
        log_success "未发现非标准位置的SUID/SGID文件"
        add_json_entry "文件系统完整性" "unusual_suid_sgid" "0" "low"
    fi
    
    # 检查隐藏文件
    log_info "搜索可疑隐藏文件..."
    # 在关键目录中查找隐藏文件和目录
    HIDDEN_FILES=$(find /home /var/www /tmp /var/tmp /dev /opt -name ".*" -type f -not -path "*/\.*" 2>/dev/null | grep -v "^/home/.*/.bash_")
    
    if [ -n "$HIDDEN_FILES" ]; then
        HIDDEN_COUNT=$(echo "$HIDDEN_FILES" | wc -l)
        log_warning "发现 $HIDDEN_COUNT 个可疑隐藏文件"
        add_json_entry "文件系统完整性" "suspicious_hidden_files" "$HIDDEN_COUNT" "medium"
        
        echo "$HIDDEN_FILES" > "$OUTPUT_DIR/integrity/suspicious_hidden_files.txt"
        echo "$HIDDEN_FILES" | head -5 | awk '{print "  - " $1}' | tee -a "$LOG_FILE"
        if [ $HIDDEN_COUNT -gt 5 ]; then
            echo "  ... 更多内容见报告文件 suspicious_hidden_files.txt" | tee -a "$LOG_FILE"
        fi
    else
        log_success "未发现可疑隐藏文件"
        add_json_entry "文件系统完整性" "suspicious_hidden_files" "0" "low"
    fi
    
    # 检查特殊属性文件
    if command -v lsattr &> /dev/null; then
        log_info "检查不可修改（immutable）文件..."
        find / -type f -exec lsattr {} \; 2>/dev/null | grep "\-\-\-\-i" > "$OUTPUT_DIR/integrity/immutable_files.txt"
        
        IMMUTABLE_COUNT=$(cat "$OUTPUT_DIR/integrity/immutable_files.txt" | wc -l)
        if [ $IMMUTABLE_COUNT -gt 0 ]; then
            log_info "发现 $IMMUTABLE_COUNT 个不可修改文件"
            add_json_entry "文件系统完整性" "immutable_files" "$IMMUTABLE_COUNT"
            
            cat "$OUTPUT_DIR/integrity/immutable_files.txt" | head -5 | awk '{print "  - " $2}' | tee -a "$LOG_FILE"
            if [ $IMMUTABLE_COUNT -gt 5 ]; then
                echo "  ... 更多内容见报告文件 immutable_files.txt" | tee -a "$LOG_FILE"
            fi
        fi
    fi
    
    # 检查.ssh目录异常
    log_info "检查SSH配置和密钥..."
    
    USER_HOMES=$(ls -la /home | grep -v "^d.*\." | grep "^d" | awk '{print $9}')
    USER_HOMES="$USER_HOMES root"
    
    for user in $USER_HOMES; do
        if [ "$user" == "root" ]; then
            SSH_DIR="/root/.ssh"
        else
            SSH_DIR="/home/$user/.ssh"
        fi
        
        if [ -d "$SSH_DIR" ]; then
            # 检查授权密钥文件
            if [ -f "$SSH_DIR/authorized_keys" ]; then
                KEYS_COUNT=$(cat "$SSH_DIR/authorized_keys" | grep -v "^$" | wc -l)
                log_info "用户 $user 的SSH授权密钥数量: $KEYS_COUNT"
                
                # 保存授权密钥到输出
                mkdir -p "$OUTPUT_DIR/ssh"
                cp "$SSH_DIR/authorized_keys" "$OUTPUT_DIR/ssh/${user}_authorized_keys.txt"
                
                # 检查是否有可疑密钥
                SUSPICIOUS_KEY=$(cat "$SSH_DIR/authorized_keys" | grep -i "ssh\-rsa AAAAB3Nza\|0x0\|hacker\|metasploit\|backd")
                if [ -n "$SUSPICIOUS_KEY" ]; then
                    log_critical "用户 $user 的SSH授权密钥中发现可疑内容"
                    add_json_entry "文件系统完整性" "${user}_suspicious_ssh_key" "是" "high"
                fi
            fi
        fi
    done
    
    # 检查Webshell
    if [ -d "/var/www" ] || [ -d "/srv/www" ] || [ -d "/var/www/html" ]; then
        log_info "检查可能的Webshell..."
        
        # 定义web目录
        WEB_DIRS=("/var/www" "/srv/www" "/var/www/html" "/usr/share/nginx/html" "/var/lib/tomcat*/webapps")
        
        # 定义可疑函数
        SUSPICIOUS_PHP=("eval(" "system(" "exec(" "passthru(" "shell_exec(" "base64_decode(" "gzinflate(" "str_rot13(" "preg_replace.*\/e" "assert(" "move_uploaded_file")
        SUSPICIOUS_JSP=("Runtime.getRuntime" "ProcessBuilder" "createStatement" "getOutputStream" ".exec(" "addShell")
        
        # 检查可疑PHP文件
        for dir in "${WEB_DIRS[@]}"; do
            if [ -d "$dir" ]; then
                for pattern in "${SUSPICIOUS_PHP[@]}"; do
                    find "$dir" -name "*.php" -type f -exec grep -l "$pattern" {} \; 2>/dev/null >> "$OUTPUT_DIR/integrity/suspicious_php_files.txt"
                done
                
                for pattern in "${SUSPICIOUS_JSP[@]}"; do
                    find "$dir" -name "*.jsp" -type f -exec grep -l "$pattern" {} \; 2>/dev/null >> "$OUTPUT_DIR/integrity/suspicious_jsp_files.txt"
                done
            fi
        done
        
        # 合并去重
        if [ -f "$OUTPUT_DIR/integrity/suspicious_php_files.txt" ]; then
            sort -u "$OUTPUT_DIR/integrity/suspicious_php_files.txt" -o "$OUTPUT_DIR/integrity/suspicious_php_files.txt"
            PHP_COUNT=$(cat "$OUTPUT_DIR/integrity/suspicious_php_files.txt" | wc -l)
            
            if [ $PHP_COUNT -gt 0 ]; then
                log_warning "发现 $PHP_COUNT 个可疑PHP文件"
                add_json_entry "文件系统完整性" "suspicious_php_files" "$PHP_COUNT" "high"
                
                cat "$OUTPUT_DIR/integrity/suspicious_php_files.txt" | head -5 | awk '{print "  - " $1}' | tee -a "$LOG_FILE"
                if [ $PHP_COUNT -gt 5 ]; then
                    echo "  ... 更多内容见报告文件 suspicious_php_files.txt" | tee -a "$LOG_FILE"
                fi
            else
                log_success "未发现可疑PHP文件"
                add_json_entry "文件系统完整性" "suspicious_php_files" "0" "low"
            fi
        fi
        
        if [ -f "$OUTPUT_DIR/integrity/suspicious_jsp_files.txt" ]; then
            sort -u "$OUTPUT_DIR/integrity/suspicious_jsp_files.txt" -o "$OUTPUT_DIR/integrity/suspicious_jsp_files.txt"
            JSP_COUNT=$(cat "$OUTPUT_DIR/integrity/suspicious_jsp_files.txt" | wc -l)
            
            if [ $JSP_COUNT -gt 0 ]; then
                log_warning "发现 $JSP_COUNT 个可疑JSP文件"
                add_json_entry "文件系统完整性" "suspicious_jsp_files" "$JSP_COUNT" "high"
            else
                log_success "未发现可疑JSP文件"
                add_json_entry "文件系统完整性" "suspicious_jsp_files" "0" "low"
            fi
        fi
    fi
    
    section_footer
}

# 检查启动项与自启程序
check_startup() {
    section_header "启动项与自启程序"
    
    # 创建启动项目录
    mkdir -p "$OUTPUT_DIR/startup"
    
    # 检查init.d脚本
    if [ -d "/etc/init.d" ]; then
        log_info "检查/etc/init.d启动脚本..."
        ls -la /etc/init.d > "$OUTPUT_DIR/startup/init.d_scripts.txt"
        INIT_COUNT=$(ls -la /etc/init.d | grep -v "^d\|^total\|^$\|^\." | wc -l)
        log_info "发现 $INIT_COUNT 个init.d启动脚本"
        add_json_entry "启动项与自启程序" "init_d_scripts" "$INIT_COUNT"
    fi
    
    # 检查rc.local文件
    if [ -f "/etc/rc.local" ]; then
        log_info "检查/etc/rc.local文件..."
        cp /etc/rc.local "$OUTPUT_DIR/startup/rc.local.txt"
        
        # 检查是否有可执行权限
        if [ -x "/etc/rc.local" ]; then
            log_info "/etc/rc.local有可执行权限"
            
            # 检查内容
            RC_LOCAL_CONTENT=$(cat /etc/rc.local | grep -v "^#\|^$\|exit 0")
            if [ -n "$RC_LOCAL_CONTENT" ]; then
                log_warning "/etc/rc.local包含自定义启动命令"
                add_json_entry "启动项与自启程序" "rc_local_custom_commands" "是" "medium"
            else
                log_success "/etc/rc.local无自定义启动命令"
                add_json_entry "启动项与自启程序" "rc_local_custom_commands" "否" "low"
            fi
        else
            log_info "/etc/rc.local无可执行权限"
        fi
    fi
    
    # 检查systemd服务
    if command -v systemctl &> /dev/null; then
        log_info "检查systemd服务..."
        
        # 列出所有启用的服务
        systemctl list-unit-files --type=service --state=enabled > "$OUTPUT_DIR/startup/enabled_services.txt"
        ENABLED_COUNT=$(systemctl list-unit-files --type=service --state=enabled | grep "enabled" | wc -l)
        log_info "发现 $ENABLED_COUNT 个已启用的systemd服务"
        add_json_entry "启动项与自启程序" "enabled_systemd_services" "$ENABLED_COUNT"
        
        # 检查自定义服务
        USER_SERVICES=$(find /etc/systemd/system -name "*.service" -type f)
        USER_SERVICE_COUNT=$(echo "$USER_SERVICES" | grep -v "^$" | wc -l)
        
        if [ $USER_SERVICE_COUNT -gt 0 ]; then
            log_info "发现 $USER_SERVICE_COUNT 个自定义systemd服务"
            add_json_entry "启动项与自启程序" "custom_systemd_services" "$USER_SERVICE_COUNT" "medium"
            
            echo "$USER_SERVICES" > "$OUTPUT_DIR/startup/custom_services.txt"
            
            # 分析每个自定义服务
            echo "$USER_SERVICES" | while read service; do
                log_info "分析服务: $service"
                cp "$service" "$OUTPUT_DIR/startup/$(basename $service)"
                
                # 检查可疑ExecStart
                SUSPICIOUS_EXEC=$(grep "ExecStart" "$service" | grep -i "wget\|curl\|nc\|ncat\|bash -i\|/tmp\|/dev/shm")
                if [ -n "$SUSPICIOUS_EXEC" ]; then
                    log_warning "服务 $service 包含可疑执行命令"
                    echo "$service: $SUSPICIOUS_EXEC" >> "$OUTPUT_DIR/startup/suspicious_services.txt"
                fi
            done
            
            if [ -f "$OUTPUT_DIR/startup/suspicious_services.txt" ]; then
                SUSP_SRV_COUNT=$(cat "$OUTPUT_DIR/startup/suspicious_services.txt" | wc -l)
                add_json_entry "启动项与自启程序" "suspicious_services" "$SUSP_SRV_COUNT" "high"
            else
                add_json_entry "启动项与自启程序" "suspicious_services" "0" "low"
            fi
        else
            log_success "未发现自定义systemd服务"
            add_json_entry "启动项与自启程序" "custom_systemd_services" "0" "low"
        fi
    fi
    
    # 检查定时任务
    log_info "检查cron定时任务..."
    
    # 系统cron任务
    for crontab in /etc/crontab /etc/cron.d/*; do
        if [ -f "$crontab" ]; then
            cp "$crontab" "$OUTPUT_DIR/startup/cron_$(basename $crontab).txt"
        fi
    done
    
    # 用户cron任务
    USER_HOMES=$(ls -la /home | grep -v "^d.*\." | grep "^d" | awk '{print $9}')
    USER_HOMES="$USER_HOMES root"
    
    SUSPICIOUS_CRON=0
    for user in $USER_HOMES; do
        # 检查用户的crontab
        if [ "$user" != "root" ]; then
            crontab -l -u "$user" > "$OUTPUT_DIR/startup/crontab_$user.txt" 2>/dev/null
        else
            crontab -l > "$OUTPUT_DIR/startup/crontab_root.txt" 2>/dev/null
        fi
        
        # 检查可疑cron任务
        if [ -f "$OUTPUT_DIR/startup/crontab_$user.txt" ]; then
            SUSP=$(cat "$OUTPUT_DIR/startup/crontab_$user.txt" | grep -i "wget\|curl\|nc\|bash -i\|/tmp\|/dev/shm\|base64\|python -c")
            
            if [ -n "$SUSP" ]; then
                log_warning "用户 $user 的cron任务中发现可疑命令"
                SUSPICIOUS_CRON=1
                echo "User $user: $SUSP" >> "$OUTPUT_DIR/startup/suspicious_crons.txt"
            fi
        fi
    done
    
    if [ $SUSPICIOUS_CRON -eq 1 ]; then
        log_critical "发现可疑cron任务，详见报告文件"
        add_json_entry "启动项与自启程序" "suspicious_crons" "是" "high"
    else
        log_success "未发现可疑cron任务"
        add_json_entry "启动项与自启程序" "suspicious_crons" "否" "low"
    fi
    
    section_footer
}

# 检查Rootkit与隐蔽进程
check_rootkits() {
    section_header "Rootkit与隐蔽进程"
    
    # 创建rootkit检查目录
    mkdir -p "$OUTPUT_DIR/rootkit"
    
    # 检查是否安装了chkrootkit
    if command -v chkrootkit &> /dev/null; then
        log_info "使用chkrootkit检测rootkit..."
        chkrootkit > "$OUTPUT_DIR/rootkit/chkrootkit_results.txt" 2>&1
        
        # 检查结果中的可疑项
        INFECTED=$(grep -i "infected" "$OUTPUT_DIR/rootkit/chkrootkit_results.txt")
        WARNING=$(grep -i "warning" "$OUTPUT_DIR/rootkit/chkrootkit_results.txt")
        FOUND=$(grep -i "found" "$OUTPUT_DIR/rootkit/chkrootkit_results.txt")
        
        if [ -n "$INFECTED" ] || [ -n "$WARNING" ] || [ -n "$FOUND" ]; then
            log_critical "chkrootkit检测到可能的rootkit感染"
            add_json_entry "Rootkit与隐蔽进程" "rootkit_detected" "是" "high"
            
            # 输出可疑结果
            if [ -n "$INFECTED" ]; then
                echo "$INFECTED" | tee -a "$LOG_FILE"
            fi
            if [ -n "$WARNING" ]; then
                echo "$WARNING" | tee -a "$LOG_FILE"
            fi
            if [ -n "$FOUND" ]; then
                echo "$FOUND" | tee -a "$LOG_FILE"
            fi
        else
            log_success "chkrootkit未检测到rootkit"
            add_json_entry "Rootkit与隐蔽进程" "rootkit_detected" "否" "low"
        fi
    else
        log_warning "未安装chkrootkit，建议安装后运行检测"
        add_json_entry "Rootkit与隐蔽进程" "chkrootkit_status" "未安装" "medium"
    fi
    
    # 检查/dev目录异常文件
    log_info "检查/dev目录异常文件..."
    IRREGULAR_DEV=$(find /dev -type f -not -path "*/dev/shm/*" 2>/dev/null)
    
    if [ -n "$IRREGULAR_DEV" ]; then
        IRREGULAR_COUNT=$(echo "$IRREGULAR_DEV" | wc -l)
        log_warning "在/dev目录下发现 $IRREGULAR_COUNT 个异常文件"
        add_json_entry "Rootkit与隐蔽进程" "irregular_dev_files" "$IRREGULAR_COUNT" "high"
        
        echo "$IRREGULAR_DEV" > "$OUTPUT_DIR/rootkit/irregular_dev_files.txt"
        echo "$IRREGULAR_DEV" | head -5 | awk '{print "  - " $1}' | tee -a "$LOG_FILE"
        if [ $IRREGULAR_COUNT -gt 5 ]; then
            echo "  ... 更多内容见报告文件 irregular_dev_files.txt" | tee -a "$LOG_FILE"
        fi
    else
        log_success "未在/dev目录下发现异常文件"
        add_json_entry "Rootkit与隐蔽进程" "irregular_dev_files" "0" "low"
    fi
    
    # 检查可疑定时任务文件
    log_info "检查可疑定时任务文件..."
    SUSPICIOUS_CRON_FILES=$(find /var/spool/cron /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly -type f -exec grep -l "wget\|curl\|tftp\|nc\|netcat\|base64\|python\|perl\|bash -i\|sh -i" {} \; 2>/dev/null)
    
    if [ -n "$SUSPICIOUS_CRON_FILES" ]; then
        SUSP_CRON_COUNT=$(echo "$SUSPICIOUS_CRON_FILES" | wc -l)
        log_warning "发现 $SUSP_CRON_COUNT 个可疑定时任务文件"
        add_json_entry "Rootkit与隐蔽进程" "suspicious_cron_files" "$SUSP_CRON_COUNT" "high"
        
        echo "$SUSPICIOUS_CRON_FILES" > "$OUTPUT_DIR/rootkit/suspicious_cron_files.txt"
    else
        log_success "未发现可疑定时任务文件"
        add_json_entry "Rootkit与隐蔽进程" "suspicious_cron_files" "0" "low"
    fi
    
    # 检查隐藏进程
    log_info "检查隐藏进程..."
    PS_COUNT=$(ps -ef | wc -l)
    PS_AUX_COUNT=$(ps aux | wc -l)
    # PS_AUX理论上比PS_EF多一行(标题行)，如果差距大，可能有隐藏进程
    DIFF=$((PS_AUX_COUNT - PS_COUNT))
    
    if [ $DIFF -gt 1 ]; then
        log_critical "检测到可能的隐藏进程，ps aux与ps -ef输出行数差距为 $DIFF"
        add_json_entry "Rootkit与隐蔽进程" "possible_hidden_processes" "$DIFF" "high"
    else
        log_success "未检测到隐藏进程"
        add_json_entry "Rootkit与隐蔽进程" "possible_hidden_processes" "0" "low"
    fi
    
    # 进程与端口关联检查
    log_info "检查进程与网络端口不匹配情况..."
    if command -v netstat &> /dev/null; then
        # 获取所有TCP/UDP监听端口
        NETSTAT_LISTEN=$(netstat -tulpn | grep "LISTEN")
        echo "$NETSTAT_LISTEN" > "$OUTPUT_DIR/rootkit/listening_ports.txt"
        
        # 提取端口和对应的PID
        echo "$NETSTAT_LISTEN" | awk '{print $7}' | cut -d/ -f1 | sort -u | grep -v "-" > "$OUTPUT_DIR/rootkit/listening_pids.txt"
        
        # 检查这些PID是否存在于进程列表中
        MISSING_PIDS=""
        while read pid; do
            if [ ! -d "/proc/$pid" ]; then
                MISSING_PIDS+="$pid "
                log_critical "发现端口关联进程PID不存在: $pid"
            fi
        done < "$OUTPUT_DIR/rootkit/listening_pids.txt"
        
        if [ -n "$MISSING_PIDS" ]; then
            log_critical "发现网络服务关联的PID不存在，可能是恶意隐藏进程"
            add_json_entry "Rootkit与隐蔽进程" "missing_port_processes" "$MISSING_PIDS" "high"
        else
            log_success "所有网络服务关联的进程均正常"
            add_json_entry "Rootkit与隐蔽进程" "missing_port_processes" "无" "low"
        fi
    fi
    
    section_footer
}

# 检查依赖和模块
check_dependencies() {
    section_header "供应链投毒检测"
    
    # 创建依赖检查目录
    mkdir -p "$OUTPUT_DIR/dependencies"
    
    # 检查Python包
    if command -v pip &> /dev/null; then
        log_info "检查Python包..."
        pip list > "$OUTPUT_DIR/dependencies/pip_list.txt" 2>/dev/null
        
        # 分析包名是否有可疑特征
        SUSPICIOUS_PACKAGES=$(cat "$OUTPUT_DIR/dependencies/pip_list.txt" | grep -i "crypto\|coin\|mine\|xmr\|monero\|backdoor\|shell\|exec\|exploit")
        
        if [ -n "$SUSPICIOUS_PACKAGES" ]; then
            log_warning "发现可疑Python包:"
            echo "$SUSPICIOUS_PACKAGES" | tee -a "$LOG_FILE"
            add_json_entry "供应链投毒检测" "suspicious_python_packages" "是" "high"
        else
            log_success "未发现可疑Python包"
            add_json_entry "供应链投毒检测" "suspicious_python_packages" "否" "low"
        fi
    fi
    
    # 检查Node.js包
    if command -v npm &> /dev/null; then
        log_info "检查Node.js包..."
        npm list -g > "$OUTPUT_DIR/dependencies/npm_global.txt" 2>/dev/null
        
        # 查找当前目录下的package.json文件
        find / -name "package.json" -type f 2>/dev/null | grep -v "node_modules" > "$OUTPUT_DIR/dependencies/package_json_files.txt"
        
        # 分析package.json中的依赖
        SUSPICIOUS_NPM=0
        while read pkg_file; do
            if [ -f "$pkg_file" ]; then
                SUSPICIOUS=$(cat "$pkg_file" | grep -i "dependencies\|devDependencies" -A 50 | grep -i "crypto\|coin\|mine\|xmr\|monero\|backdoor\|shell\|exec\|exploit")
                
                if [ -n "$SUSPICIOUS" ]; then
                    log_warning "在 $pkg_file 中发现可疑Node.js包"
                    echo "$pkg_file: $SUSPICIOUS" >> "$OUTPUT_DIR/dependencies/suspicious_npm.txt"
                    SUSPICIOUS_NPM=1
                fi
            fi
        done < "$OUTPUT_DIR/dependencies/package_json_files.txt"
        
        if [ $SUSPICIOUS_NPM -eq 1 ]; then
            add_json_entry "供应链投毒检测" "suspicious_node_packages" "是" "high"
        else
            log_success "未发现可疑Node.js包"
            add_json_entry "供应链投毒检测" "suspicious_node_packages" "否" "low"
        fi
    fi
    
    # 检查Go依赖
    if command -v go &> /dev/null; then
        log_info "检查Go依赖..."
        
        # 查找go.mod文件
        find / -name "go.mod" -type f 2>/dev/null > "$OUTPUT_DIR/dependencies/go_mod_files.txt"
        
        # 分析go.mod依赖
        SUSPICIOUS_GO=0
        while read mod_file; do
            if [ -f "$mod_file" ]; then
                SUSPICIOUS=$(cat "$mod_file" | grep -i "crypto\|coin\|mine\|xmr\|monero\|backdoor\|shell\|exec\|exploit")
                
                if [ -n "$SUSPICIOUS" ]; then
                    log_warning "在 $mod_file 中发现可疑Go依赖"
                    echo "$mod_file: $SUSPICIOUS" >> "$OUTPUT_DIR/dependencies/suspicious_go.txt"
                    SUSPICIOUS_GO=1
                fi
            fi
        done < "$OUTPUT_DIR/dependencies/go_mod_files.txt"
        
        if [ $SUSPICIOUS_GO -eq 1 ]; then
            add_json_entry "供应链投毒检测" "suspicious_go_packages" "是" "high"
        else
            log_success "未发现可疑Go依赖"
            add_json_entry "供应链投毒检测" "suspicious_go_packages" "否" "low"
        fi
    fi
    
    # 检查内核模块
    log_info "检查内核模块..."
    lsmod > "$OUTPUT_DIR/dependencies/kernel_modules.txt"
    
    # 检查可疑模块名称
    SUSPICIOUS_MODULES=$(cat "$OUTPUT_DIR/dependencies/kernel_modules.txt" | grep -i "hide\|secret\|crypto\|coin\|mine\|stealth\|rootkit")
    
    if [ -n "$SUSPICIOUS_MODULES" ]; then
        log_warning "发现可疑内核模块:"
        echo "$SUSPICIOUS_MODULES" | tee -a "$LOG_FILE"
        add_json_entry "供应链投毒检测" "suspicious_kernel_modules" "是" "high"
    else
        log_success "未发现可疑内核模块"
        add_json_entry "供应链投毒检测" "suspicious_kernel_modules" "否" "low"
    fi
    
    section_footer
}

# 检查容器安全
check_containers() {
    section_header "容器与虚拟化环境检测"
    
    # 创建容器检查目录
    mkdir -p "$OUTPUT_DIR/containers"
    
    # 检查是否安装了Docker
    if command -v docker &> /dev/null; then
        log_info "检测到Docker环境，检查容器安全..."
        
        # 检查Docker版本
        DOCKER_VERSION=$(docker version 2>/dev/null | grep "Version" | head -1 | awk '{print $2}')
        log_info "Docker版本: $DOCKER_VERSION"
        add_json_entry "容器与虚拟化环境检测" "docker_version" "$DOCKER_VERSION"
        
        # 列出所有容器
        log_info "列出所有容器..."
        docker ps -a > "$OUTPUT_DIR/containers/docker_containers.txt" 2>/dev/null
        CONTAINER_COUNT=$(docker ps -a 2>/dev/null | grep -v "CONTAINER ID" | wc -l)
        log_info "发现 $CONTAINER_COUNT 个Docker容器"
        add_json_entry "容器与虚拟化环境检测" "docker_containers" "$CONTAINER_COUNT"
        
        # 检查正在运行的容器
        RUNNING_COUNT=$(docker ps 2>/dev/null | grep -v "CONTAINER ID" | wc -l)
        log_info "当前有 $RUNNING_COUNT 个正在运行的容器"
        add_json_entry "容器与虚拟化环境检测" "running_containers" "$RUNNING_COUNT"
        
        # 列出所有镜像
        log_info "列出所有镜像..."
        docker images > "$OUTPUT_DIR/containers/docker_images.txt" 2>/dev/null
        IMAGE_COUNT=$(docker images 2>/dev/null | grep -v "REPOSITORY" | wc -l)
        log_info "发现 $IMAGE_COUNT 个Docker镜像"
        add_json_entry "容器与虚拟化环境检测" "docker_images" "$IMAGE_COUNT"
        
        # 检查特权容器
        PRIVILEGED_CONTAINERS=$(docker ps --quiet --all --filter ancestor=priviledged 2>/dev/null)
        if [ -n "$PRIVILEGED_CONTAINERS" ]; then
            log_critical "发现特权容器，这可能导致主机安全风险"
            add_json_entry "容器与虚拟化环境检测" "privileged_containers" "是" "high"
        else
            log_success "未发现特权容器"
            add_json_entry "容器与虚拟化环境检测" "privileged_containers" "否" "low"
        fi
        
        # 检查Docker守护进程配置
        if [ -f "/etc/docker/daemon.json" ]; then
            log_info "分析Docker守护进程配置..."
            cp "/etc/docker/daemon.json" "$OUTPUT_DIR/containers/daemon.json"
            
            # 检查是否禁用了内容信任
            CONTENT_TRUST=$(cat "/etc/docker/daemon.json" | grep -i "content-trust")
            if [ -z "$CONTENT_TRUST" ]; then
                log_warning "Docker未启用内容信任，建议启用"
                add_json_entry "容器与虚拟化环境检测" "docker_content_trust" "未启用" "medium"
            else
                log_success "Docker已启用内容信任"
                add_json_entry "容器与虚拟化环境检测" "docker_content_trust" "已启用" "low"
            fi
        fi
    else
        log_info "未检测到Docker环境"
        add_json_entry "容器与虚拟化环境检测" "docker_installed" "否" "low"
    fi
    
    # 检查是否安装了Kubernetes
    if command -v kubectl &> /dev/null; then
        log_info "检测到Kubernetes环境，检查K8s安全..."
        
        # 检查K8s版本
        K8S_VERSION=$(kubectl version 2>/dev/null | grep "Client Version" | head -1 | awk '{print $5}')
        log_info "Kubernetes客户端版本: $K8S_VERSION"
        add_json_entry "容器与虚拟化环境检测" "kubernetes_version" "$K8S_VERSION"
        
        # 尝试获取集群信息
        if kubectl cluster-info &>/dev/null; then
            log_info "成功连接到Kubernetes集群"
            
            # 列出所有Pod
            log_info "列出所有Pod..."
            kubectl get pods --all-namespaces > "$OUTPUT_DIR/containers/kubernetes_pods.txt" 2>/dev/null
            POD_COUNT=$(kubectl get pods --all-namespaces 2>/dev/null | grep -v "NAMESPACE" | wc -l)
            log_info "发现 $POD_COUNT 个Kubernetes Pod"
            add_json_entry "容器与虚拟化环境检测" "kubernetes_pods" "$POD_COUNT"
            
            # 检查特权Pod
            PRIV_PODS=$(kubectl get pods --all-namespaces -o json 2>/dev/null | grep -i "privileged.*true" | wc -l)
            if [ $PRIV_PODS -gt 0 ]; then
                log_warning "发现 $PRIV_PODS 个特权Pod，这可能导致安全风险"
                add_json_entry "容器与虚拟化环境检测" "privileged_pods" "$PRIV_PODS" "high"
            else
                log_success "未发现特权Pod"
                add_json_entry "容器与虚拟化环境检测" "privileged_pods" "0" "low"
            fi
            
            # 检查敏感挂载
            SENSITIVE_MOUNTS=$(kubectl get pods --all-namespaces -o json 2>/dev/null | grep -i "hostPath" | wc -l)
            if [ $SENSITIVE_MOUNTS -gt 0 ]; then
                log_warning "发现 $SENSITIVE_MOUNTS 个hostPath挂载，可能存在主机文件系统访问风险"
                add_json_entry "容器与虚拟化环境检测" "host_path_mounts" "$SENSITIVE_MOUNTS" "medium"
            else
                log_success "未发现hostPath挂载"
                add_json_entry "容器与虚拟化环境检测" "host_path_mounts" "0" "low"
            fi
        else
            log_warning "无法连接到Kubernetes集群"
            add_json_entry "容器与虚拟化环境检测" "kubernetes_connected" "否" "medium"
        fi
    else
        log_info "未检测到Kubernetes环境"
        add_json_entry "容器与虚拟化环境检测" "kubernetes_installed" "否" "low"
    fi
    
    # 检查是否在容器内部运行
    if [ -f "/.dockerenv" ] || [ -f "/run/.containerenv" ]; then
        log_warning "当前脚本正在容器内部运行，无法完全检测主机安全性"
        add_json_entry "容器与虚拟化环境检测" "running_inside_container" "是" "medium"
    else
        log_info "当前脚本在主机环境中运行"
        add_json_entry "容器与虚拟化环境检测" "running_inside_container" "否" "low"
    fi
    
    section_footer
}

# 快速隔离措施
security_response() {
    section_header "快速隔离措施"
    
    log_info "提供可选的安全响应措施..."
    
    # 创建响应目录
    mkdir -p "$OUTPUT_DIR/response"
    
    # 生成关闭高危端口的脚本
    cat > "$OUTPUT_DIR/response/close_dangerous_ports.sh" << 'EOF'
#!/bin/bash
# 关闭高危端口的脚本

# 定义高危端口
DANGEROUS_PORTS=("21" "23" "445" "3389" "5900" "8080" "6379" "11211" "27017" "1433" "5432")

# 检查并配置iptables
if command -v iptables &> /dev/null; then
    echo "使用iptables关闭高危端口..."
    
    for port in "${DANGEROUS_PORTS[@]}"; do
        iptables -A INPUT -p tcp --dport $port -j DROP
        iptables -A INPUT -p udp --dport $port -j DROP
        echo "已关闭端口 $port"
    done
    
    # 保存iptables规则
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || \
        iptables-save > /etc/iptables.conf 2>/dev/null
        echo "已保存iptables规则"
    else
        echo "警告: 无法保存iptables规则，重启后将失效"
    fi
fi

echo "高危端口关闭完成"
EOF
    chmod +x "$OUTPUT_DIR/response/close_dangerous_ports.sh"
    log_info "已生成关闭高危端口的脚本: $OUTPUT_DIR/response/close_dangerous_ports.sh"
    
    # 生成断开可疑连接的脚本
    cat > "$OUTPUT_DIR/response/terminate_suspicious.sh" << 'EOF'
#!/bin/bash
# 断开可疑网络连接的脚本

echo "查找可疑网络连接..."

# 定义可疑的远程端口
SUSPICIOUS_PORTS=("4444" "1080" "6666" "8080" "31337" "12345" "5555")

# 查找并断开连接到可疑端口的连接
for port in "${SUSPICIOUS_PORTS[@]}"; do
    CONNECTIONS=$(netstat -tpn 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d/ -f1)
    
    if [ -n "$CONNECTIONS" ]; then
        echo "发现连接到可疑端口 $port 的进程:"
        for pid in $CONNECTIONS; do
            if [ "$pid" != "-" ]; then
                PROCESS=$(ps -p $pid -o comm= 2>/dev/null)
                echo "PID: $pid, 进程: $PROCESS"
                echo -n "是否终止此进程? [y/N] "
                read answer
                if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
                    kill -9 $pid 2>/dev/null
                    if [ $? -eq 0 ]; then
                        echo "进程 $pid 已终止"
                    else
                        echo "无法终止进程 $pid"
                    fi
                fi
            fi
        done
    fi
done

echo "可疑连接检查完成"
EOF
    chmod +x "$OUTPUT_DIR/response/terminate_suspicious.sh"
    log_info "已生成断开可疑连接的脚本: $OUTPUT_DIR/response/terminate_suspicious.sh"
    
    # 生成备份关键文件的脚本
    cat > "$OUTPUT_DIR/response/backup_critical.sh" << 'EOF'
#!/bin/bash
# 备份关键系统文件的脚本

BACKUP_DIR="/root/system_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "开始备份关键系统文件到 $BACKUP_DIR..."

# 备份关键配置文件
echo "备份系统配置文件..."
cp -p /etc/passwd "$BACKUP_DIR/" 2>/dev/null
cp -p /etc/shadow "$BACKUP_DIR/" 2>/dev/null
cp -p /etc/group "$BACKUP_DIR/" 2>/dev/null
cp -p /etc/hosts "$BACKUP_DIR/" 2>/dev/null
cp -p /etc/fstab "$BACKUP_DIR/" 2>/dev/null
cp -p /etc/crontab "$BACKUP_DIR/" 2>/dev/null
cp -rp /etc/cron.* "$BACKUP_DIR/" 2>/dev/null
cp -rp /etc/ssh "$BACKUP_DIR/" 2>/dev/null
cp -p /etc/sudoers "$BACKUP_DIR/" 2>/dev/null

# 备份关键日志文件
echo "备份系统日志文件..."
mkdir -p "$BACKUP_DIR/logs"
cp -p /var/log/auth.log "$BACKUP_DIR/logs/" 2>/dev/null
cp -p /var/log/secure "$BACKUP_DIR/logs/" 2>/dev/null
cp -p /var/log/syslog "$BACKUP_DIR/logs/" 2>/dev/null
cp -p /var/log/messages "$BACKUP_DIR/logs/" 2>/dev/null
cp -p /var/log/kern.log "$BACKUP_DIR/logs/" 2>/dev/null
cp -p /var/log/dpkg.log "$BACKUP_DIR/logs/" 2>/dev/null
cp -p /var/log/yum.log "$BACKUP_DIR/logs/" 2>/dev/null

# 备份重要服务配置
echo "备份重要服务配置..."
if [ -d "/etc/nginx" ]; then
    cp -rp /etc/nginx "$BACKUP_DIR/" 2>/dev/null
fi
if [ -d "/etc/apache2" ]; then
    cp -rp /etc/apache2 "$BACKUP_DIR/" 2>/dev/null
fi
if [ -d "/etc/httpd" ]; then
    cp -rp /etc/httpd "$BACKUP_DIR/" 2>/dev/null
fi
if [ -d "/etc/mysql" ]; then
    cp -rp /etc/mysql "$BACKUP_DIR/" 2>/dev/null
fi

# 创建备份摘要
echo "生成备份摘要..."
find "$BACKUP_DIR" -type f | sort > "$BACKUP_DIR/files_list.txt"
echo "备份完成时间: $(date)" > "$BACKUP_DIR/backup_info.txt"

# 压缩备份
echo "压缩备份文件..."
tar -czf "${BACKUP_DIR}.tar.gz" "$BACKUP_DIR" 2>/dev/null

# 如果有GPG可用，加密备份
if command -v gpg &> /dev/null; then
    echo "备份可以使用以下命令加密:"
    echo "gpg -c ${BACKUP_DIR}.tar.gz"
fi

echo "备份完成，备份文件位于: ${BACKUP_DIR}.tar.gz"
EOF
    chmod +x "$OUTPUT_DIR/response/backup_critical.sh"
    log_info "已生成备份关键文件的脚本: $OUTPUT_DIR/response/backup_critical.sh"
    
    # 为最终报告生成HTML格式
    cat > "$OUTPUT_DIR/response/generate_html_report.sh" << 'EOF'
#!/bin/bash
# 生成HTML格式的报告

if [ $# -ne 1 ]; then
    echo "用法: $0 <JSON报告文件>"
    exit 1
fi

JSON_REPORT="$1"
OUTPUT_HTML="${JSON_REPORT%.json}.html"

if [ ! -f "$JSON_REPORT" ]; then
    echo "错误: 找不到JSON报告文件 $JSON_REPORT"
    exit 1
fi

# 生成HTML报告
echo "生成HTML报告: $OUTPUT_HTML"

cat > "$OUTPUT_HTML" << 'HTML_EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux系统安全检查报告</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .section {
            margin-bottom: 30px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .finding {
            margin: 10px 0;
            padding: 10px;
            border-radius: 3px;
        }
        .high {
            background-color: #ffebee;
            border-left: 5px solid #f44336;
        }
        .medium {
            background-color: #fff8e1;
            border-left: 5px solid #ffc107;
        }
        .low {
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
        }
        .info {
            background-color: #e3f2fd;
            border-left: 5px solid #2196f3;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f5f5f5;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .summary-item {
            text-align: center;
            padding: 10px;
            border-radius: 5px;
            flex: 1;
            margin: 0 5px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .timestamp {
            font-size: 0.9em;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Linux系统安全检查报告</h1>
        <div class="timestamp" id="scan-time"></div>
    </div>
    
    <div class="summary" id="summary">
        <!-- 将由JavaScript填充 -->
    </div>
    
    <div id="report-content">
        <!-- 将由JavaScript填充 -->
    </div>
    
    <script>
        // 加载JSON数据
        const reportData = JSON_DATA_PLACEHOLDER;
        
        // 设置扫描时间
        document.getElementById('scan-time').textContent = `扫描时间: ${reportData.scan_time}`;
        
        // 统计风险计数
        let highCount = 0;
        let mediumCount = 0;
        let lowCount = 0;
        
        // 创建报告内容
        const reportContent = document.getElementById('report-content');
        
        for (const [sectionName, sectionData] of Object.entries(reportData.results)) {
            // 创建区段
            const sectionDiv = document.createElement('div');
            sectionDiv.className = 'section';
            
            // 添加区段标题
            const sectionTitle = document.createElement('h2');
            sectionTitle.textContent = sectionName;
            sectionDiv.appendChild(sectionTitle);
            
            // 创建表格
            const table = document.createElement('table');
            const thead = document.createElement('thead');
            const headerRow = document.createElement('tr');
            
            const thItem = document.createElement('th');
            thItem.textContent = '检查项';
            headerRow.appendChild(thItem);
            
            const thValue = document.createElement('th');
            thValue.textContent = '结果';
            headerRow.appendChild(thValue);
            
            const thRisk = document.createElement('th');
            thRisk.textContent = '风险级别';
            headerRow.appendChild(thRisk);
            
            thead.appendChild(headerRow);
            table.appendChild(thead);
            
            const tbody = document.createElement('tbody');
            
            // 添加检查项
            for (const [itemName, itemValue] of Object.entries(sectionData)) {
                const row = document.createElement('tr');
                
                const tdItem = document.createElement('td');
                tdItem.textContent = itemName;
                row.appendChild(tdItem);
                
                const tdValue = document.createElement('td');
                const tdRisk = document.createElement('td');
                
                if (typeof itemValue === 'object') {
                    tdValue.textContent = itemValue.value;
                    tdRisk.textContent = itemValue.risk || 'info';
                    
                    if (itemValue.risk === 'high') {
                        row.className = 'high';
                        highCount++;
                    } else if (itemValue.risk === 'medium') {
                        row.className = 'medium';
                        mediumCount++;
                    } else if (itemValue.risk === 'low') {
                        row.className = 'low';
                        lowCount++;
                    } else {
                        row.className = 'info';
                    }
                } else {
                    tdValue.textContent = itemValue;
                    tdRisk.textContent = 'info';
                    row.className = 'info';
                }
                
                row.appendChild(tdValue);
                row.appendChild(tdRisk);
                tbody.appendChild(row);
            }
            
            table.appendChild(tbody);
            sectionDiv.appendChild(table);
            reportContent.appendChild(sectionDiv);
        }
        
        // 更新摘要
        const summary = document.getElementById('summary');
        
        const highItem = document.createElement('div');
        highItem.className = 'summary-item high';
        highItem.innerHTML = `<h3>高风险</h3><p>${highCount}</p>`;
        summary.appendChild(highItem);
        
        const mediumItem = document.createElement('div');
        mediumItem.className = 'summary-item medium';
        mediumItem.innerHTML = `<h3>中风险</h3><p>${mediumCount}</p>`;
        summary.appendChild(mediumItem);
        
        const lowItem = document.createElement('div');
        lowItem.className = 'summary-item low';
        lowItem.innerHTML = `<h3>低风险</h3><p>${lowCount}</p>`;
        summary.appendChild(lowItem);
    </script>
</body>
</html>
HTML_EOF

# 替换JSON数据
JSON_CONTENT=$(cat "$JSON_REPORT")
sed -i "s|JSON_DATA_PLACEHOLDER|$JSON_CONTENT|g" "$OUTPUT_HTML"

echo "HTML报告已生成: $OUTPUT_HTML"
EOF
    chmod +x "$OUTPUT_DIR/response/generate_html_report.sh"
    log_info "已生成HTML报告转换脚本: $OUTPUT_DIR/response/generate_html_report.sh"
    
    log_info "可使用以下命令运行响应脚本:"
    echo "  关闭高危端口: $OUTPUT_DIR/response/close_dangerous_ports.sh"
    echo "  断开可疑连接: $OUTPUT_DIR/response/terminate_suspicious.sh"
    echo "  备份关键文件: $OUTPUT_DIR/response/backup_critical.sh"
    echo "  生成HTML报告: $OUTPUT_DIR/response/generate_html_report.sh $JSON_REPORT" | tee -a "$LOG_FILE"
    
    section_footer
}

# 生成安全修复建议
generate_recommendations() {
    section_header "安全修复建议"
    
    # 创建建议目录
    mkdir -p "$OUTPUT_DIR/recommendations"
    
    log_info "根据扫描结果生成安全修复建议..."
    
    # 用户安全
# 主函数
main() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}= Linux系统安全检查工具 v1.0          =${NC}"
    echo -e "${BLUE}= 扫描开始时间: $(date)        =${NC}"
    echo -e "${BLUE}=========================================${NC}"
    
    echo -e "报告将保存到目录: ${GREEN}$OUTPUT_DIR${NC}\n"
    
    # 检查root权限
    check_root
    
    # 收集系统信息
    collect_system_info
    
    # 检查用户与账户信息
    check_users
    
    # 检查进程
    check_processes
    
    # 检查网络连接
    check_network_connections
    
    # 检查开放服务
    check_services
    
    # 检查日志
    check_logs
    
    # 检查历史操作记录
    check_history
    
    # 检查审计系统
    check_audit
    
    # 检查文件系统完整性
    check_file_integrity
    
    # 检查启动项
    check_startup
    
    # 检查Rootkit与隐蔽进程
    check_rootkits
    
    # 检查依赖和模块
    check_dependencies
    
    # 检查容器安全
    check_containers
    
    # 后续会添加更多函数调用...
    
    # 完成JSON报告
    sed -i '$ s/,$//' "$JSON_REPORT"
    echo '  }' >> "$JSON_REPORT"
    echo '}' >> "$JSON_REPORT"
    
    echo -e "\n${BLUE}=========================================${NC}"
    echo -e "${BLUE}= 扫描完成时间: $(date)        =${NC}"
    echo -e "${BLUE}= 报告已保存到: $OUTPUT_DIR ${NC}"
    echo -e "${BLUE}=========================================${NC}"
}

# 执行主函数
main 