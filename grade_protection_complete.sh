#!/bin/bash

# =====================
# 全局变量和配置
# =====================
# 设置输出文件
OUTPUT_DIR="grade_protection_results_$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="$OUTPUT_DIR/grade_protection_report.txt"
HTML_REPORT="$OUTPUT_DIR/grade_protection_report.html"
PDF_REPORT="$OUTPUT_DIR/grade_protection_report.pdf"

# 创建输出目录
mkdir -p $OUTPUT_DIR

# =====================
# 基础函数
# =====================
# 输出函数
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp][$level] $message" | tee -a $REPORT_FILE
    
    # 添加到HTML报告
    case "$level" in
        "INFO") color="black" ;;
        "WARNING") color="orange" ;;
        "CRITICAL") color="red" ;;
        *) color="black" ;;
    esac
    echo "<p style='color: $color'>[$timestamp][$level] $message</p>" >> $HTML_REPORT
}

# 配置文件检查和加载
check_config() {
    if [ ! -f "config.conf" ]; then
        log_message "CRITICAL" "配置文件 config.conf 不存在"
        exit 1
    fi
    source config.conf
    
    # 验证必要的配置项
    local required_configs=(
        "MYSQL_HOST" "MYSQL_PORT" "MYSQL_USER"
        "IMPORTANT_DIRS" "CRITICAL_PROCESSES" "SENSITIVE_PORTS"
        "AUDIT_LOG_DIRS" "SECURE_FILE_PERMISSIONS"
    )
    
    for config in "${required_configs[@]}"; do
        if [ -z "${!config}" ]; then
            log_message "CRITICAL" "配置项 $config 未设置"
            exit 1
        fi
    done
}

# 工具检查函数
check_required_tools() {
    log_message "INFO" "=== 检查必要工具 ==="
    
    # 基础工具
    BASIC_TOOLS=(
        "netstat:网络连接检查"
        "ss:套接字统计"
        "ip:网络配置"
        "ps:进程状态"
        "grep:文本搜索"
        "awk:文本处理"
        "find:文件查找"
    )
    
    # 可选工具
    OPTIONAL_TOOLS=(
        "mysql:数据库安全检查"
        "redis-cli:Redis安全检查"
        "docker:容器安全检查"
        "kubectl:kubernetes集群检查"
        "apache2|nginx:Web服务器检查"
        "lynis:系统安全审计"
        "nikto:Web应用漏洞扫描"
        "nmap:端口扫描"
        "cryptsetup:磁盘加密检查"
        "auditd:审计系统"
        "firewalld|ufw:防火墙"
    )
    
    # 检查工具
    check_tool_availability() {
        local tool_info="$1"
        local is_basic="$2"
        
        local tool="${tool_info%%:*}"
        local desc="${tool_info#*:}"
        
        if [[ $tool == *"|"* ]]; then
            local found=false
            for alt_tool in ${tool//|/ }; do
                if command -v "$alt_tool" >/dev/null 2>&1; then
                    found=true
                    break
                fi
            done
            if ! $found; then
                if [ "$is_basic" = true ]; then
                    log_message "CRITICAL" "缺少基础工具: $tool ($desc)"
                    return 1
                else
                    log_message "WARNING" "缺少可选工具: $tool ($desc)"
                fi
            fi
        else
            if ! command -v "$tool" >/dev/null 2>&1; then
                if [ "$is_basic" = true ]; then
                    log_message "CRITICAL" "缺少基础工具: $tool ($desc)"
                    return 1
                else
                    log_message "WARNING" "缺少可选工具: $tool ($desc)"
                fi
            fi
        fi
        return 0
    }
    
    # 检查基础工具
    local basic_failed=false
    for tool in "${BASIC_TOOLS[@]}"; do
        if ! check_tool_availability "$tool" true; then
            basic_failed=true
        fi
    done
    
    if [ "$basic_failed" = true ]; then
        log_message "INFO" "请安装缺少的基础工具："
        log_message "INFO" "CentOS/RHEL: sudo yum install -y net-tools iproute2 procps-ng grep gawk findutils"
        log_message "INFO" "Ubuntu/Debian: sudo apt install -y net-tools iproute2 procps grep gawk findutils"
        exit 1
    fi
    
    # 检查可选工具
    local optional_missing=false
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if ! check_tool_availability "$tool" false; then
            optional_missing=true
        fi
    done
    
    if [ "$optional_missing" = true ]; then
        log_message "WARNING" "部分功能可能无法使用"
        log_message "INFO" "建议安装以下包："
        log_message "INFO" "CentOS/RHEL: sudo yum install -y mysql-server redis docker-ce kubernetes-client apache2 lynis nikto nmap cryptsetup audit firewalld mutt"
        log_message "INFO" "Ubuntu/Debian: sudo apt install -y mysql-server redis-tools docker.io kubectl apache2 lynis nikto nmap cryptsetup auditd ufw mutt"
        
        read -p "是否继续执行检查？[y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# =====================
# 检查函数
# =====================

# 初始化HTML报告
initialize_html_report() {
    cat > $HTML_REPORT << EOF
<!DOCTYPE html>
<html>
<head>
    <title>等保测评报告 - $(date '+%Y-%m-%d')</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1, h2 { color: #333; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .warning { color: orange; }
        .critical { color: red; }
        .info { color: black; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <h1>等保测评报告</h1>
    <div class="section">
        <h2>测评时间：$(date '+%Y-%m-%d %H:%M:%S')</h2>
EOF
}

# 1. 身份鉴别检查
check_identification() {
    log_message "INFO" "=== 1. 身份鉴别安全检查 ==="
    
    # 1.1 检查密码复杂度策略
    log_message "INFO" "1.1 密码复杂度策略检查"
    if [ -f /etc/security/pwquality.conf ]; then
        grep -E "minlen|dcredit|ucredit|lcredit|ocredit" /etc/security/pwquality.conf >> $REPORT_FILE
        
        # 检查是否符合配置要求
        min_len=$(grep "^minlen" /etc/security/pwquality.conf | awk '{print $3}')
        if [ -n "$min_len" ] && [ "$min_len" -lt "$PASSWORD_MIN_LENGTH" ]; then
            log_message "WARNING" "密码最小长度($min_len)小于要求的${PASSWORD_MIN_LENGTH}"
        fi
    else
        log_message "WARNING" "未找到密码复杂度配置文件"
    fi
    
    # 1.2 检查密码有效期
    log_message "INFO" "1.2 密码有效期检查"
    local pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    if [ -n "$pass_max_days" ] && [ "$pass_max_days" -gt "$PASSWORD_MAX_AGE" ]; then
        log_message "WARNING" "密码最大有效期($pass_max_days)超过要求的${PASSWORD_MAX_AGE}天"
    fi
    
    # 1.3 检查空密码账户
    log_message "INFO" "1.3 空密码账户检查"
    local empty_pass=$(awk -F: '($2=="")' /etc/shadow)
    if [ ! -z "$empty_pass" ]; then
        log_message "CRITICAL" "发现空密码账户：\n$empty_pass"
    fi
}

# 2. 访问控制检查
check_access_control() {
    log_message "INFO" "=== 2. 访问控制检查 ==="
    
    # 2.1 检查特权账户
    log_message "INFO" "2.1 特权账户检查"
    local root_users=$(awk -F: '$3==0 {print $1}' /etc/passwd)
    for user in $root_users; do
        if [ "$user" != "root" ]; then
            log_message "CRITICAL" "发现非root用户具有root权限：$user"
        fi
    done
    
    # 2.2 检查文件权限
    log_message "INFO" "2.2 重要文件权限检查"
    for perm in "${SECURE_FILE_PERMISSIONS[@]}"; do
        local file="${perm%%:*}"
        local required_mode="${perm##*:}"
        if [ -f "$file" ]; then
            local current_mode=$(stat -c "%a" "$file")
            if [ "$current_mode" != "$required_mode" ]; then
                log_message "WARNING" "文件 $file 权限不正确: 当前=$current_mode, 应为=$required_mode"
            fi
        fi
    done
    
    # 2.3 检查SUID文件
    log_message "INFO" "2.3 SUID文件检查"
    find / -type f -perm -4000 2>/dev/null | while read -r file; do
        log_message "WARNING" "发现SUID文件：$file"
    done
}

# 3. 安全审计检查
check_security_audit() {
    log_message "INFO" "=== 3. 安全审计检查 ==="
    
    # 3.1 检查审计系统状态
    log_message "INFO" "3.1 审计系统状态"
    if systemctl is-active auditd >/dev/null 2>&1; then
        log_message "INFO" "审计系统运行正常"
        
        # 检查审计规则
        for cmd in "${AUDIT_COMMANDS[@]}"; do
            if ! auditctl -l | grep -q "$cmd"; then
                log_message "WARNING" "命令 $cmd 未配置审计规则"
            fi
        done
    else
        log_message "CRITICAL" "审计系统未运行"
    fi
    
    # 3.2 检查日志完整性
    log_message "INFO" "3.2 日志完整性检查"
    for log_dir in "${AUDIT_LOG_DIRS[@]}"; do
        if [ -d "$log_dir" ]; then
            local log_files=$(find "$log_dir" -type f -name "*.log" -mtime -7)
            if [ -z "$log_files" ]; then
                log_message "WARNING" "目录 $log_dir 中未找到最近7天的日志文件"
            fi
        else
            log_message "WARNING" "日志目录 $log_dir 不存在"
        fi
    done
}

# 4. 入侵防范检查
check_intrusion_prevention() {
    log_message "INFO" "=== 4. 入侵防范检查 ==="
    
    # 4.1 检查防火墙状态
    log_message "INFO" "4.1 防火墙状态"
    if systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --list-all >> $REPORT_FILE
    elif systemctl is-active ufw >/dev/null 2>&1; then
        ufw status verbose >> $REPORT_FILE
    else
        log_message "WARNING" "防火墙未运行"
    fi
    
    # 4.2 检查开放端口
    log_message "INFO" "4.2 开放端口检查"
    local open_ports=$(netstat -tulnp | grep "LISTEN")
    echo "$open_ports" >> $REPORT_FILE
    
    # 检查敏感端口
    for port in "${SENSITIVE_PORTS[@]}"; do
        port_num="${port%%[[:space:]]*}"
        if echo "$open_ports" | grep -q ":$port_num "; then
            log_message "WARNING" "发现开放的敏感端口：$port"
        fi
    done
}

# 5. 数据安全检查
check_data_security() {
    log_message "INFO" "=== 5. 数据安全检查 ==="
    
    # 5.1 检查磁盘加密
    log_message "INFO" "5.1 磁盘加密检查"
    if command -v cryptsetup >/dev/null 2>&1; then
        cryptsetup status >> $REPORT_FILE
    else
        log_message "WARNING" "未安装磁盘加密工具"
    fi
    
    # 5.2 检查重要目录备份
    log_message "INFO" "5.2 备份检查"
    if [ -d "$BACKUP_DIR" ]; then
        find "$BACKUP_DIR" -type f -mtime -"$BACKUP_RETENTION_DAYS" >> $REPORT_FILE
    else
        log_message "WARNING" "备份目录 $BACKUP_DIR 不存在"
    fi
    
    # 5.3 检查重要文件权限
    log_message "INFO" "5.3 重要文件权限检查"
    for dir in "${IMPORTANT_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            find "$dir" -type f -perm -o+w >> $REPORT_FILE
        fi
    done
}

# 6. 数据库安全检查
check_database_security() {
    log_message "INFO" "=== 6. 数据库安全检查 ==="
    
    # 6.1 MySQL检查
    check_mysql_security
    
    # 6.2 Redis检查
    check_redis_security
}

# MySQL安全检查
check_mysql_security() {
    log_message "INFO" "6.1 MySQL安全检查"
    if command -v mysql >/dev/null 2>&1; then
        # 版本信息
        mysql --version >> $REPORT_FILE
        
        # 检查空密码账户
        mysql -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" \
            -e "SELECT user,host FROM mysql.user WHERE authentication_string='';" >> $REPORT_FILE 2>/dev/null
        
        # 检查配置
        mysql -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" \
            -e "SHOW VARIABLES LIKE '%timeout%';" >> $REPORT_FILE 2>/dev/null
        
        # 检查日志状态
        mysql -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" \
            -e "SHOW VARIABLES LIKE '%log%';" >> $REPORT_FILE 2>/dev/null
    else
        log_message "INFO" "MySQL未安装"
    fi
}

# Redis安全检查
check_redis_security() {
    log_message "INFO" "6.2 Redis安全检查"
    if command -v redis-cli >/dev/null 2>&1; then
        # 版本信息
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" info server >> $REPORT_FILE
        
        # 检查密码保护
        if [ -z "$REDIS_PASSWORD" ]; then
            log_message "WARNING" "Redis未设置密码"
        fi
        
        # 检查配置
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" info Keyspace >> $REPORT_FILE
    else
        log_message "INFO" "Redis未安装"
    fi
}

# 7. Web服务安全检查
check_web_security() {
    log_message "INFO" "=== 7. Web服务安全检查 ==="
    
    # 7.1 检查Web服务器配置
    log_message "INFO" "7.1 Web服务器配置检查"
    for config in "${WEB_CONFIG_FILES[@]}"; do
        if [ -f "$config" ]; then
            grep -i "security" "$config" >> $REPORT_FILE
        fi
    done
    
    # 7.2 检查SSL证书
    log_message "INFO" "7.2 SSL证书检查"
    for cert_path in "${SSL_CERT_PATHS[@]}"; do
        if [ -d "$cert_path" ]; then
            find "$cert_path" -type f -name "*.pem" -exec openssl x509 -noout -dates -in {} \; >> $REPORT_FILE
        fi
    done
    
    # 7.3 Web漏洞扫描
    if command -v nikto >/dev/null 2>&1; then
        log_message "INFO" "7.3 Web漏洞扫描"
        nikto $NIKTO_OPTIONS -h localhost >> $REPORT_FILE
    fi
}

# 8. 容器安全检查
check_container_security() {
    log_message "INFO" "=== 8. 容器安全检查 ==="
    
    # 8.1 Docker检查
    if command -v docker >/dev/null 2>&1; then
        log_message "INFO" "8.1 Docker安全检查"
        # 检查Docker版本
        docker version >> $REPORT_FILE
        
        # 检查运行容器
        docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}" >> $REPORT_FILE
        
        # 检查Docker配置
        docker info | grep -E "Security|Logging" >> $REPORT_FILE
        
        # 检查镜像
        for image in "${DOCKER_ALLOWED_IMAGES[@]}"; do
            if ! docker images | grep -q "$image"; then
                log_message "WARNING" "未找到允许的镜像：$image"
            fi
        done
    fi
    
    # 8.2 Kubernetes检查
    if command -v kubectl >/dev/null 2>&1; then
        log_message "INFO" "8.2 Kubernetes安全检查"
        # 检查集群状态
        kubectl cluster-info >> $REPORT_FILE
        
        # 检查命名空间
        for ns in "${K8S_NAMESPACES[@]}"; do
            kubectl get pods -n "$ns" >> $REPORT_FILE
        done
    fi
}

# 9. 网络安全检查
check_network_security() {
    log_message "INFO" "=== 9. 网络安全检查 ==="
    
    # 9.1 检查网络接口
    log_message "INFO" "9.1 网络接口检查"
    ip addr show >> $REPORT_FILE
    
    # 9.2 检查路由表
    log_message "INFO" "9.2 路由表检查"
    ip route >> $REPORT_FILE
    
    # 9.3 检查网络连接
    log_message "INFO" "9.3 网络连接检查"
    netstat -natp >> $REPORT_FILE
    
    # 9.4 检查IP地址范围
    log_message "INFO" "9.4 IP地址范围检查"
    for range in "${ALLOWED_IP_RANGES[@]}"; do
        if ! ip addr | grep -q "$range"; then
            log_message "WARNING" "未找到允许的IP范围：$range"
        fi
    done
}

# 10. 漏洞扫描
check_vulnerabilities() {
    log_message "INFO" "=== 10. 漏洞扫描 ==="
    
    # 10.1 系统漏洞扫描
    if command -v nmap >/dev/null 2>&1; then
        log_message "INFO" "10.1 系统漏洞扫描"
        nmap $NMAP_SCAN_TYPE localhost \
            --exclude-ports $SCAN_EXCLUDE_PORTS \
            --exclude $SCAN_EXCLUDE_IPS >> $REPORT_FILE
    fi
    
    # 10.2 Web应用漏洞扫描
    if command -v nikto >/dev/null 2>&1; then
        log_message "INFO" "10.2 Web应用漏洞扫描"
        nikto $NIKTO_OPTIONS -h localhost >> $REPORT_FILE
    fi
    
    # 10.3 系统安全审计
    if command -v lynis >/dev/null 2>&1; then
        log_message "INFO" "10.3 系统安全审计"
        lynis audit system $LYNIS_OPTIONS >> $REPORT_FILE
    fi
}

# 11. 报告生成和发送
generate_report() {
    log_message "INFO" "=== 生成报告 ==="
    
    # 11.1 生成HTML报告
    finalize_html_report
    
    # 11.2 生成PDF报告（如果安装了wkhtmltopdf）
    if command -v wkhtmltopdf >/dev/null 2>&1; then
        wkhtmltopdf "$HTML_REPORT" "$PDF_REPORT"
        log_message "INFO" "PDF报告已生成：$PDF_REPORT"
    fi
}

# 完成HTML报告
finalize_html_report() {
    # 添加报告摘要
    echo "<div class='section'>" >> $HTML_REPORT
    echo "<h2>报告摘要</h2>" >> $HTML_REPORT
    echo "<table>" >> $HTML_REPORT
    echo "<tr><th>检查项</th><th>状态</th></tr>" >> $HTML_REPORT
    
    # 统计各类问题
    local critical_count=$(grep -c "\[CRITICAL\]" $REPORT_FILE)
    local warning_count=$(grep -c "\[WARNING\]" $REPORT_FILE)
    local info_count=$(grep -c "\[INFO\]" $REPORT_FILE)
    
    echo "<tr><td>严重问题</td><td class='critical'>$critical_count</td></tr>" >> $HTML_REPORT
    echo "<tr><td>警告</td><td class='warning'>$warning_count</td></tr>" >> $HTML_REPORT
    echo "<tr><td>信息</td><td class='info'>$info_count</td></tr>" >> $HTML_REPORT
    echo "</table></div>" >> $HTML_REPORT
    
    # 关闭HTML文档
    cat >> $HTML_REPORT << EOF
    </div>
    <div class="section">
        <h2>测评结束时间：$(date '+%Y-%m-%d %H:%M:%S')</h2>
    </div>
</body>
</html>
EOF
}

# 主函数
main() {
    if [ "$EUID" -ne 0 ]; then 
        echo "请使用root权限运行此脚本"
        exit 1
    fi
    
    # 检查配置和工具
    check_config
    check_required_tools
    
    # 初始化报告
    initialize_html_report
    log_message "INFO" "开始等保测评检查..."
    
    # 执行所有检查
    check_identification
    check_access_control
    check_security_audit
    check_intrusion_prevention
    check_data_security
    check_database_security
    check_web_security
    check_container_security
    check_network_security
    check_vulnerabilities
    
    # 生成报告
    generate_report
    
    log_message "INFO" "测评检查完成"
    log_message "INFO" "文本报告：$REPORT_FILE"
    log_message "INFO" "HTML报告：$HTML_REPORT"
    [ -f "$PDF_REPORT" ] && log_message "INFO" "PDF报告：$PDF_REPORT"
}

# 执行主函数
main
 