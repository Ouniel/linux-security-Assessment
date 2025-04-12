#!/bin/bash
# Linux应急响应检查脚本 v4.0
# 功能：直接在终端输出关键系统信息，带彩色分割线
# 增强版：增加更多安全检查项，支持结果导出

# 判断是否禁用颜色
USE_COLORS=true
# 检查是否在非交互式终端或管道中运行
if [ ! -t 1 ]; then
    USE_COLORS=false
fi

# 定义颜色函数，根据设置决定是否使用颜色
set_colors() {
    if [ "$USE_COLORS" = true ]; then
        # 增强颜色方案
        RED='\033[1;31m'        # 加粗红色
        GREEN='\033[1;32m'      # 加粗绿色
        YELLOW='\033[1;33m'     # 加粗黄色
        BLUE='\033[1;34m'       # 加粗蓝色
        PURPLE='\033[1;35m'     # 加粗紫色
        CYAN='\033[1;36m'       # 加粗青色
        WHITE='\033[1;37m'      # 加粗白色
        ORANGE='\033[0;33m'     # 橙色
        GRAY='\033[0;37m'       # 灰色
        NC='\033[0m'            # 无颜色
    else
        # 无颜色模式
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        PURPLE=''
        CYAN=''
        WHITE=''
        ORANGE=''
        GRAY=''
        NC=''
    fi
}

# 应用颜色设置
set_colors

# 确保使用bash执行
if [ -z "$BASH_VERSION" ]; then
    echo -e "\033[1;31m此脚本需要使用bash执行，请使用 'bash $0' 命令运行\033[0m"
    exit 1
fi

# 设置退出陷阱，确保清理临时文件
trap cleanup_temp_files EXIT INT TERM

OUTPUT_FILE=""

# 使用说明
usage() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║            ${WHITE}Linux应急响应脚本 v4.0${BLUE}                     ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}用法:${NC} $0 [选项]"
    echo -e "${YELLOW}选项:${NC}"
    echo -e "  ${GREEN}-o <文件>${NC}    将结果保存到指定文件"
    echo -e "  ${GREEN}-h${NC}           显示此帮助信息"
    exit 1
}

# 处理参数
while getopts "o:h" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG" ;;
        h) usage ;;
        \?) usage ;;
    esac
done

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        exit 1
    fi
}

# 输出函数
output() {
    echo -e "$1"
    if [ -n "$OUTPUT_FILE" ]; then
        echo "$1" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> "$OUTPUT_FILE"
    fi
}

divider() {
    output "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
}

header() {
    divider
    output "${BLUE}║${YELLOW}        $1${BLUE}        ║${NC}"
    divider
}

# 初始化输出文件
init_output_file() {
    if [ -n "$OUTPUT_FILE" ]; then
        echo "# Linux应急响应报告 - $(date)" > "$OUTPUT_FILE"
        echo "# 主机名: $(hostname)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
}

# 添加进度条功能
progress_bar() {
    local percent=$1
    local done=$(($percent * 40 / 100))
    local remaining=$((40 - done))
    
    echo -ne "\r${CYAN}进度: [${NC}"
    printf "${GREEN}%${done}s${NC}" | tr ' ' '█'
    printf "${GRAY}%${remaining}s${NC}" | tr ' ' '░'
    echo -e "${CYAN}] ${WHITE}$percent%%${NC}"
}

# 网络流量分析
analyze_network_traffic() {
    header "网络流量分析"
    
    output "${GREEN}┏━━━━━━━━━━━━━━━━━━ 当前网络连接状态统计 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 使用保存的连接信息
    output "$(cat /tmp/er_netstat_tuapn.tmp | awk '{print $6}' | sort | uniq -c | sort -rn)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 连接源IP统计 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 使用ss代替netstat，并优先使用之前保存的信息
    output "$(cat /tmp/er_netstat_established.tmp | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    if command -v tcpdump >/dev/null 2>&1; then
        output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 实时流量样本分析 ━━━━━━━━━━━━━━━━━━┓${NC}"
        output "捕获5秒网络流量样本..."
        
        # 使用mktemp创建安全的临时文件
        local traffic_file=$(mktemp /tmp/traffic_sample.XXXXXX)
        
        # 启动tcpdump进程并保存PID
        tcpdump -i any -c 100 -w "$traffic_file" >/dev/null 2>&1 &
        local tcpdump_pid=$!
        
        sleep 5
        # 安全终止tcpdump进程
        kill -TERM $tcpdump_pid 2>/dev/null
        # 等待进程结束
        wait $tcpdump_pid 2>/dev/null
        
        output "捕获完成，分析结果:"
        output "$(tcpdump -r "$traffic_file" -n -c 50 2>/dev/null)"
        
        # 立即清理临时文件
        rm -f "$traffic_file"
        output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    else
        output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 网络流量分析 ━━━━━━━━━━━━━━━━━━┓${NC}"
        output "无法进行实时流量分析，tcpdump未安装"
        output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    fi
    
    # 检查异常端口
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 检测非常见端口监听 ━━━━━━━━━━━━━━━━━━┓${NC}"
    local common_ports="22 80 443 25 21 53 3306 5432 8080 8443 3389 6379 27017 9000 9090 9200 5601 2049 111 137 138 139 445"
    local listening=$(cat /tmp/er_netstat_listening.tmp | grep -E 'LISTEN' | awk '{print $4}' | awk -F":" '{print $NF}')
    
    for port in $listening; do
        local is_common=false
        for common in $common_ports; do
            if [ "$port" = "$common" ]; then
                is_common=true
                break
            fi
        done
        
        if [ "$is_common" = false ]; then
            local process=$(cat /tmp/er_netstat_listening.tmp | grep ":$port" | awk '{print $7}')
            output "发现非常见端口: $port ($process)"
        fi
    done
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    # 检查网络接口混杂模式
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 网络接口混杂模式检查 ━━━━━━━━━━━━━━━━━━┓${NC}"
    if ip link show | grep -i promisc >/dev/null; then
        output "${RED}警告：发现处于混杂模式的网络接口：${NC}"
        output "$(ip link show | grep -i promisc)"
    else
        output "未发现处于混杂模式的网络接口"
    fi
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    # DNS设置检查
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ DNS设置检查 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "nameserver配置："
    output "$(cat /etc/resolv.conf 2>/dev/null | grep nameserver)"
    
    # 检查hosts文件异常条目
    output "\nhosts文件异常条目："
    output "$(grep -v '^#\|^$\|^\s*\|^127.0.0.1 localhost\|^::1' /etc/hosts 2>/dev/null)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

# SSH日志安全分析
analyze_ssh_logs() {
    header "SSH日志安全分析"
    
    # 检测日志文件位置
    local latest_log=""
    
    # 首先尝试查找auth.log文件
    for log_file in /var/log/auth.log /var/log/auth.log.1; do
        if [ -f "$log_file" ]; then
            latest_log="$log_file"
            break
        fi
    done
    
    # 如果没找到auth.log，尝试secure日志
    if [ -z "$latest_log" ]; then
        for log_file in /var/log/secure /var/log/secure.1; do
            if [ -f "$log_file" ]; then
                latest_log="$log_file"
                break
            fi
        done
    fi
    
    if [ -z "$latest_log" ]; then
        output "${RED}未找到认证日志文件${NC}"
        return
    fi
    
    output "${GREEN}----- 使用 $latest_log 进行分析 -----${NC}"
    
    # 1. 检测尝试爆破SSH root账号的IP
    output "\n${GREEN}----- 尝试爆破SSH root账号的IP -----${NC}"
    local root_brute_force=$(grep -a "Failed password for root" "$latest_log" | awk '{print $11}' | sort | uniq -c | sort -nr)
    if [ -n "$root_brute_force" ]; then
        output "$root_brute_force"
        
        # 获取爆破IP列表（按IP从小到大排序）
        local root_brute_ips=$(grep -a "Failed password for root" "$latest_log" | awk '{print $11}' | sort -V | uniq | tr '\n' ',' | sed 's/,$//')
        output "\n${RED}爆破root的IP列表：${NC}$root_brute_ips"
        
        # 统计总爆破次数
        local total_root_attempts=$(grep -a "Failed password for root" "$latest_log" | wc -l)
        output "\n${YELLOW}针对root的总爆破尝试次数：${NC}$total_root_attempts"
    else
        output "未发现针对root账号的爆破行为"
    fi
    
    # 2. 检测SSH爆破成功登录的IP
    output "\n${GREEN}----- SSH爆破成功登录的IP -----${NC}"
    local success_login=$(grep -a "Accepted " "$latest_log" | awk '{print $11}' | sort | uniq -c | sort -nr)
    if [ -n "$success_login" ]; then
        output "$success_login"
        
        # 获取成功登录IP列表
        local success_ips=$(grep -a "Accepted " "$latest_log" | awk '{print $11}' | sort -V | uniq | tr '\n' ',' | sed 's/,$//')
        output "\n${RED}成功登录的IP列表：${NC}$success_ips"
        
        # 分析成功登录的用户名
        local success_users=$(grep -a "Accepted " "$latest_log" | awk '{print $9}' | sort | uniq -c | sort -nr)
        output "\n${YELLOW}成功登录的用户：${NC}"
        output "$success_users"
    else
        output "未发现成功登录记录"
    fi
    
    # 3. 检测爆破用户名字典
    output "\n${GREEN}----- 爆破使用的用户名字典 -----${NC}"
    if command -v perl >/dev/null 2>&1; then
        local username_dict=$(grep -a "Failed password" "$latest_log" | perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}' | sort | uniq -c | sort -nr)
        if [ -n "$username_dict" ]; then
            output "$username_dict"
            
            # 获取用户名列表
            local usernames=$(grep -a "Failed password" "$latest_log" | perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}' | sort | uniq | tr '\n' ',' | sed 's/,$//')
            output "\n${RED}尝试的用户名列表：${NC}$usernames"
            
            # 统计不同用户名的尝试次数
            local total_user_attempts=$(grep -a "Failed password" "$latest_log" | wc -l)
            output "\n${YELLOW}总爆破尝试次数：${NC}$total_user_attempts"
        else
            output "未发现用户名字典"
        fi
    else
        output "无法分析用户名字典（需要perl支持）"
        
        # 使用替代方案
        local alt_username_dict=$(grep -a "Failed password" "$latest_log" | awk '{print $9}' | sort | uniq -c | sort -nr)
        if [ -n "$alt_username_dict" ]; then
            output "替代分析方法结果:"
            output "$alt_username_dict"
        fi
    fi
    
    # 4. 检测登录成功的IP共爆破了多少次
    output "\n${GREEN}----- 登录成功的IP的爆破次数 -----${NC}"
    for ip in $(grep -a "Accepted " "$latest_log" | awk '{print $11}' | sort | uniq); do
        local brute_count=$(grep -a "Failed password" "$latest_log" | grep "$ip" | wc -l)
        local success_count=$(grep -a "Accepted " "$latest_log" | grep "$ip" | wc -l)
        output "IP ${YELLOW}$ip${NC} 尝试爆破次数: ${RED}$brute_count${NC}，成功登录次数: ${GREEN}$success_count${NC}"
        
        # 计算成功率
        if [ $brute_count -gt 0 ]; then
            local success_rate=$(( (success_count * 100) / (brute_count + success_count) ))
            output "  - 爆破成功率: ${YELLOW}$success_rate%${NC}"
        fi
    done
    
    # 5. 检测新建用户（可能的后门用户）
    output "\n${GREEN}----- 检测新建用户 -----${NC}"
    local new_users=$(grep -a "new user" "$latest_log" | grep -v "useradd\[")
    if [ -n "$new_users" ]; then
        output "${RED}发现新建用户:${NC}"
        output "$new_users"
        
        # 提取新用户名
        local usernames=$(grep -a "new user" "$latest_log" | grep -v "useradd\[" | awk -F"name=" '{print $2}' | awk '{print $1}')
        output "\n${RED}新建用户名列表：${NC}$usernames"
        
        # 检查新用户是否有登录行为
        output "\n${YELLOW}检查新建用户的登录行为：${NC}"
        for user in $usernames; do
            local user_logins=$(grep -a "$user" "$latest_log" | grep -a "Accepted ")
            if [ -n "$user_logins" ]; then
                output "${RED}警告: 新建用户 $user 有登录行为！${NC}"
                output "$user_logins"
            else
                output "新建用户 $user 无登录记录"
            fi
        done
    else
        output "未发现新建用户"
    fi
    
    # 6. 检测可疑的权限提升
    output "\n${GREEN}----- 检测可疑的权限提升 -----${NC}"
    local sudo_usage=$(grep -a "sudo:" "$latest_log" | grep "COMMAND=")
    if [ -n "$sudo_usage" ]; then
        output "${YELLOW}发现sudo使用记录:${NC}"
        output "$sudo_usage" | tail -n 10
        
        # 可疑命令分析
        output "\n${YELLOW}可疑sudo命令分析：${NC}"
        local suspicious_cmds=$(grep -a "sudo:" "$latest_log" | grep -E "COMMAND=.*(chmod \+s|passwd|useradd|groupadd|chattr|visudo|usermod.*wheel|sh -c|base64)" | tail -n 10)
        if [ -n "$suspicious_cmds" ]; then
            output "${RED}发现可疑的sudo命令：${NC}"
            output "$suspicious_cmds"
        else
            output "未发现明显可疑的sudo命令"
        fi
    else
        output "未发现sudo使用记录"
    fi
    
    # 7. 检测SSH登录时间分布
    output "\n${GREEN}----- SSH登录时间分布 -----${NC}"
    local login_hours=$(grep -a "Accepted " "$latest_log" | awk '{print $3}' | sort | uniq -c | sort -k2n)
    if [ -n "$login_hours" ]; then
        output "登录时间分布:"
        output "$login_hours"
        
        # 检测非工作时间登录
        local off_hours=$(grep -a "Accepted " "$latest_log" | awk '{if ($3 >= "00:" && $3 < "07:") print}')
        if [ -n "$off_hours" ]; then
            output "\n${YELLOW}发现非工作时间登录 (00:00-07:00)：${NC}"
            output "$off_hours" | head -n 5
        fi
    else
        output "无法分析登录时间分布"
    fi
}

# 找出差异的PID
# 替换过程替换语法，使用临时文件方式比较
diff_pids() {
    local list1="$1"
    local list2="$2"
    local temp_file1=$(mktemp)
    local temp_file2=$(mktemp)
    
    echo "$list1" > "$temp_file1"
    echo "$list2" > "$temp_file2"
    
    # 使用comm命令比较差异
    local result=$(comm -3 "$temp_file1" "$temp_file2")
    
    # 清理临时文件
    rm -f "$temp_file1" "$temp_file2"
    
    # 返回结果
    echo "$result"
}

# 检查隐藏进程
check_hidden_proc() {
    # 比较进程列表差异
    ps_1=$(ps -ef | grep -v "ps -ef" | grep -v grep | sort -n | md5sum)
    ps_2=$(ps aux | grep -v "ps aux" | grep -v grep | sort -n | md5sum)
    
    if [ "$ps_1" != "$ps_2" ]; then
        output "${RED}警告: 进程列表不一致，可能存在隐藏进程${NC}"
        
        # 尝试识别隐藏进程
        pid_list_1=$(ps -ef | awk '{print $2}' | sort -n)
        pid_list_2=$(ps aux | awk '{print $2}' | sort -n)
        
        # 找出差异的PID
        diff_pid_result=$(diff_pids "$pid_list_1" "$pid_list_2")
        
        if [ -n "$diff_pid_result" ]; then
            output "可能的隐藏进程PID: $diff_pid_result"
            # 尝试使用其他方法获取这些进程的信息
            for pid in $diff_pid_result; do
                if [ -d "/proc/$pid" ]; then
                    output "PID $pid 进程信息:"
                    output "命令行: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
                    output "状态: $(cat /proc/$pid/status 2>/dev/null | grep -E 'Name|State|PPid')"
                fi
            done
        fi
    else
        output "未检测到隐藏进程"
    fi
}

# 查找SSH密钥
find_ssh_keys() {
    # 系统范围的SSH密钥
    system_keys="/etc/ssh/ssh_host_*_key*"
    output "系统SSH密钥:"
    output "$(ls -la $system_keys 2>/dev/null)"
    
    # 用户SSH密钥
    output "\n用户SSH密钥和授权密钥:"
    for user_home in /home/*/ /root/; do
        user=$(basename "$user_home")
        if [ -d "$user_home.ssh" ]; then
            output "\n用户 $user SSH密钥:"
            output "$(ls -la $user_home.ssh/ 2>/dev/null)"
            
            # 检查authorized_keys文件
            if [ -f "$user_home.ssh/authorized_keys" ]; then
                output "\n$user authorized_keys:"
                output "密钥数量: $(grep -v '^#' $user_home.ssh/authorized_keys 2>/dev/null | grep -v '^$' | wc -l)"
                
                # 检查可疑的授权密钥
                if [ -n "$(grep -i 'command=' $user_home.ssh/authorized_keys 2>/dev/null)" ]; then
                    output "${RED}警告: 发现带有command=的授权密钥 (可能是受限SSH或后门)${NC}"
                    output "$(grep -i 'command=' $user_home.ssh/authorized_keys 2>/dev/null)"
                fi
            fi
        fi
    done
    
    # 查找最近添加的SSH密钥
    output "\n最近添加的SSH密钥 (7天内):"
    output "$(find /home /root -path '*/.ssh/*' -type f -name 'id_*' -o -name 'authorized_keys' -mtime -7 -ls 2>/dev/null)"
}

# 检查临时目录可疑文件
check_tmp_files() {
    # 检查临时目录
    tmp_locations="/tmp /var/tmp /dev/shm /run/shm"
    for tmp_dir in $tmp_locations; do
        if [ -d "$tmp_dir" ]; then
            output "检查 $tmp_dir 目录:"
            
            # 可执行文件
            output "可执行文件:"
            output "$(find $tmp_dir -type f -perm -100 -o -perm -010 -o -perm -001 -ls 2>/dev/null | head -n 10)"
            
            # 脚本文件
            output "\n脚本文件:"
            output "$(find $tmp_dir -type f -name "*.sh" -o -name "*.pl" -o -name "*.py" -o -name "*.php" -ls 2>/dev/null | head -n 10)"
            
            # 奇怪的隐藏文件
            output "\n隐藏文件:"
            output "$(find $tmp_dir -name ".*" -type f -ls 2>/dev/null | head -n 10)"
            
            # 大文件
            output "\n大文件 (>10MB):"
            output "$(find $tmp_dir -type f -size +10M -ls 2>/dev/null | head -n 5)"
        fi
    done
}

# 优化: 收集系统信息到变量
collect_process_info() {
    PS_AUX=$(ps aux 2>/dev/null)
    PS_EF=$(ps -ef 2>/dev/null)
    NETSTAT_TULPN=$(netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null)
    NETSTAT_TUAPN=$(netstat -tuapn 2>/dev/null || ss -tuapn 2>/dev/null)
    NETSTAT_ESTABLISHED=$(echo "$NETSTAT_TUAPN" | grep ESTABLISHED)
    NETSTAT_LISTENING=$(echo "$NETSTAT_TULPN" | grep LISTEN)
    LSOF_NETWORK=$(lsof -i 2>/dev/null)
    IP_ADDR=$(ip addr 2>/dev/null || ifconfig -a 2>/dev/null)
    IP_ROUTE=$(ip route 2>/dev/null || route -n 2>/dev/null)
    IP_NEIGH=$(ip neigh 2>/dev/null || arp -a 2>/dev/null)
    
    # 保存到临时文件以减少内存使用
    echo "$PS_AUX" > /tmp/er_ps_aux.tmp
    echo "$PS_EF" > /tmp/er_ps_ef.tmp
    echo "$NETSTAT_TULPN" > /tmp/er_netstat_tulpn.tmp
    echo "$NETSTAT_TUAPN" > /tmp/er_netstat_tuapn.tmp
    echo "$NETSTAT_ESTABLISHED" > /tmp/er_netstat_established.tmp
    echo "$NETSTAT_LISTENING" > /tmp/er_netstat_listening.tmp
    echo "$LSOF_NETWORK" > /tmp/er_lsof_network.tmp
    echo "$IP_ADDR" > /tmp/er_ip_addr.tmp
    echo "$IP_ROUTE" > /tmp/er_ip_route.tmp
    echo "$IP_NEIGH" > /tmp/er_ip_neigh.tmp
}

# 清理临时文件
cleanup_temp_files() {
    echo -e "${GREEN}清理临时文件...${NC}"
    rm -f /tmp/er_*.tmp /tmp/traffic_sample.* 2>/dev/null
}

# 扩展rootkit和恶意软件检测列表
detect_rootkits() {
    header "RootKit检测"
    
    output "${GREEN}┏━━━━━━━━━━━━━━━━━━ 检查隐藏进程 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 比较进程列表差异
    ps_1=$(ps -ef | grep -v "ps -ef" | grep -v grep | sort -n | md5sum)
    ps_2=$(ps aux | grep -v "ps aux" | grep -v grep | sort -n | md5sum)
    
    if [ "$ps_1" != "$ps_2" ]; then
        output "${RED}警告: 进程列表不一致，可能存在隐藏进程${NC}"
    else
        output "未检测到隐藏进程"
    fi
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 检查隐藏端口 ━━━━━━━━━━━━━━━━━━┓${NC}"
    netstat_1=$(netstat -an | sort | md5sum)
    ss_1=$(ss -an | sort | md5sum)
    
    if [ "$netstat_1" != "$ss_1" ]; then
        output "${RED}警告: 端口列表不一致，可能存在隐藏端口${NC}"
    else
        output "未检测到隐藏端口"
    fi
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 检查常见Rootkit文件和目录 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 扩展的Rootkit路径列表
    local rootkit_paths="
    /dev/.hdlc /dev/.mdmin /dev/.rd /dev/ttyop /dev/ttyoa 
    /lib/modules/*/extra /usr/bin/sshd /usr/local/bin/sshd 
    /usr/bin/ssh /usr/sbin/sshd
    /tmp/.bash /tmp/.bash_history /tmp/.lsattr /tmp/.uname 
    /tmp/.dir /tmp/.system /tmp/.sshrc /tmp/.bashrc 
    /var/tmp/.bash /var/tmp/.system /var/tmp/.uname
    /etc/.pwd.lock /etc/.profile /.qaU7EmgXXX /.Xsession
    /etc/rc.d/rc.local~ /etc/rc.d/rc.local.bak
    /usr/include/asm/timex.h /usr/include/linux/sockios.h
    /usr/include/rpc/types.h /usr/include/asm/exec.h
    /usr/share/locale/zh/LC_MESSAGES/.k
    /usr/share/locale/zh/LC_MESSAGES/.x
    /lib/.libselinux.so /usr/share/man/man1/linsniffer.1
    /usr/share/locale/ko/LC_MESSAGES/.x
    /usr/share/locale/ko/LC_MESSAGES/.k
    /usr/share/locale/sk/LC_MESSAGES/.x
    /usr/share/locale/sk/LC_MESSAGES/.k
    /usr/share/locale/ja/LC_MESSAGES/.x
    /usr/share/locale/ja/LC_MESSAGES/.k"
    
    found_rootkit=false
    for path in $rootkit_paths; do
        if [ -e "$path" ]; then
            output "${RED}警告: 可能的Rootkit路径存在: $path${NC}"
            output "文件详情: $(ls -la $path 2>/dev/null)"
            found_rootkit=true
        fi
    done
    
    if [ "$found_rootkit" = false ]; then
        output "未发现已知Rootkit文件路径"
    fi
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 检查可疑内核模块 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 扩展的可疑模块列表
    local suspicious_mods="
    hide_lkm adore modhide kldetour phide kinsmod
    knark wkmr rpldev kkeylogger subversions
    heroin kis kis_old kitrap kloadi
    synapsys adutux xsyslog xsyslog_old rtf
    superkit taskigt tuxkit_8 tkd2 anonoying
    sebek cleaner kbdv4 kbdv3 prrf
    skt serzan sneaky zk nkh
    sshdoor rootkit"
    
    local loaded_modules=$(lsmod | awk '{print $1}')
    local found_suspicious_mod=false
    
    for mod in $suspicious_mods; do
        if echo "$loaded_modules" | grep -q "$mod"; then
            output "${RED}警告: 可疑内核模块: $mod${NC}"
            found_suspicious_mod=true
        fi
    done
    
    if [ "$found_suspicious_mod" = false ]; then
        output "未发现已知可疑内核模块"
    fi
    
    # 检查模块文件修改日期
    output "\n检查内核模块文件修改时间异常:"
    local kernel_ver=$(uname -r)
    local module_path="/lib/modules/$kernel_ver"
    
    if [ -d "$module_path" ]; then
        local module_files=$(find $module_path -name "*.ko" -mtime -30 2>/dev/null | head -n 10)
        if [ -n "$module_files" ]; then
            output "${YELLOW}最近30天内修改的内核模块文件:${NC}"
            output "$module_files"
        else
            output "未发现最近修改的内核模块文件"
        fi
    fi
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 检查LKM劫持 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 检查系统调用表可能被劫持
    if [ -f "/proc/kallsyms" ]; then
        output "系统调用表查看:"
        output "$(grep -E 'sys_call_table|ia32_sys_call_table' /proc/kallsyms 2>/dev/null)"
        
        # 检查可疑的系统调用
        output "\n可疑的系统调用重写:"
        suspicious_syscalls=$(grep -E 'sys_(read|write|open|getdents|getdents64|kill|mkdir|rmdir|creat|unlink)' /proc/kallsyms 2>/dev/null | grep -v "_syscall" | grep -v "sys_call_table")
        if [ -n "$suspicious_syscalls" ]; then
            output "${RED}警告: 可能存在系统调用被劫持:${NC}"
            output "$suspicious_syscalls"
        else
            output "未发现明显的系统调用劫持"
        fi
    else
        output "无法检查系统调用表 (/proc/kallsyms 不可读)"
    fi
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

# 系统安全基线检查
security_baseline_check() {
    header "系统安全基线检查"
    
    local pass_count=0
    local fail_count=0
    local warn_count=0
    local total_checks=0
    
    # 检查函数
    check_item() {
        local check_name="$1"
        local check_command="$2"
        local remediation="$3"
        local result
        
        total_checks=$((total_checks + 1))
        result=$(eval "$check_command" 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            output "[${GREEN}通过${NC}] $check_name"
            pass_count=$((pass_count + 1))
        else
            output "[${RED}失败${NC}] $check_name"
            output "    建议: $remediation"
            fail_count=$((fail_count + 1))
        fi
    }
    
    # 密码策略
    output "${GREEN}----- 密码策略 -----${NC}"
    check_item "密码最短长度>=8" "grep -E \"^PASS_MIN_LEN[[:space:]]+[8-9]|^PASS_MIN_LEN[[:space:]]+[0-9]{2,}\" /etc/login.defs" "编辑/etc/login.defs，设置PASS_MIN_LEN参数至少为8"
    check_item "密码到期时间<=90天" "grep \"PASS_MAX_DAYS[[:space:]]*[0-9]\\{1,2\\}$\" /etc/login.defs" "编辑/etc/login.defs，设置PASS_MAX_DAYS参数不超过90"
    
    # SSH安全
    output "\n${GREEN}----- SSH安全 -----${NC}"
    check_item "禁止Root远程登录" "grep \"^PermitRootLogin[[:space:]]*no\" /etc/ssh/sshd_config" "在/etc/ssh/sshd_config中设置PermitRootLogin no"
    check_item "禁止空密码登录" "grep \"^PermitEmptyPasswords[[:space:]]*no\" /etc/ssh/sshd_config" "在/etc/ssh/sshd_config中设置PermitEmptyPasswords no"
    check_item "SSH协议版本2" "! grep \"^Protocol[[:space:]]*1\" /etc/ssh/sshd_config" "在/etc/ssh/sshd_config中设置Protocol 2"
    
    # 文件权限
    output "\n${GREEN}----- 文件权限 -----${NC}"
    check_item "passwd文件权限644" "[ $(stat -c %a /etc/passwd) = '644' ]" "修改/etc/passwd权限为644: chmod 644 /etc/passwd"
    check_item "shadow文件权限400或000" "[ $(stat -c %a /etc/shadow) = '400' ] || [ $(stat -c %a /etc/shadow) = '000' ]" "修改/etc/shadow权限为400: chmod 400 /etc/shadow"
    check_item "group文件权限644" "[ $(stat -c %a /etc/group) = '644' ]" "修改/etc/group权限为644: chmod 644 /etc/group"
    
    # 网络安全
    output "\n${GREEN}----- 网络安全 -----${NC}"
    check_item "禁用ICMP重定向" "sysctl -n net.ipv4.conf.all.accept_redirects | grep -E '^0$'" "设置内核参数: echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf"
    check_item "启用IP转发保护" "sysctl -n net.ipv4.conf.all.accept_source_route | grep -E '^0$'" "设置内核参数: echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.conf"
    check_item "防火墙已启用" "systemctl is-active firewalld >/dev/null 2>&1 || systemctl is-active ufw >/dev/null 2>&1 || iptables -L | grep -i policy" "启用防火墙服务: systemctl enable --now firewalld"
    
    # 账户安全
    output "\n${GREEN}----- 账户安全 -----${NC}"
    check_item "无空密码账户" "! grep -E '^[^:]+:+::' /etc/shadow" "删除或设置空密码账户的密码"
    check_item "所有账户拥有密码" "! grep -E '^[^:]+:[^!*]' /etc/passwd | grep -v -f <(grep -E '^[^:]+:[^!*]' /etc/shadow)" "为所有活动账户设置密码"
    
    # 审计
    output "\n${GREEN}----- 审计 -----${NC}"
    check_item "审计服务已启用" "systemctl is-active auditd >/dev/null 2>&1" "启用审计服务: systemctl enable --now auditd"
    
    # 总结
    output "\n${GREEN}----- 基线检查总结 -----${NC}"
    output "总检查项: $total_checks"
    output "通过: $pass_count"
    output "失败: $fail_count"
    output "合规率: $(( pass_count * 100 / total_checks ))%"
}

# 高级威胁检测
check_advanced_threats() {
    header "高级威胁检测"
    
    # 1. 检测异常外部连接
    output "${GREEN}----- 检测主动外部连接 -----${NC}"
    local established_conns=$(netstat -antp 2>/dev/null | grep ESTABLISHED)
    output "活跃连接列表:"
    output "$established_conns"
    
    # 识别可疑的外部连接
    output "\n${GREEN}----- 可疑外部连接分析 -----${NC}"
    local suspicious_ports="5896 4444 1080 8080 6666 31337"
    local suspicious_found=false
    
    for port in $suspicious_ports; do
        local sus_conn=$(echo "$established_conns" | grep ":$port")
        if [ -n "$sus_conn" ]; then
            output "${RED}警告: 发现连接到可疑端口 $port:${NC}"
            output "$sus_conn"
            suspicious_found=true
        fi
    done
    
    if [ "$suspicious_found" = false ]; then
        output "未发现连接到已知恶意端口"
    fi
    
    # 2. 检测近期创建/修改的文件
    output "\n${GREEN}----- 近期创建/修改的文件 (24小时内) -----${NC}"
    local recently_changed=$(find / -path /proc -prune -o -path /sys -prune -o -type f -ctime -1 -ls 2>/dev/null | grep -v "/var/log" | head -n 20)
    output "$recently_changed"
    
    # 3. 检测关键目录下的可疑文件
    output "\n${GREEN}----- 关键目录可疑文件检查 -----${NC}"
    local suspicious_dirs="/tmp /usr/bin /usr/libexec /usr/local/bin /var/tmp /dev/shm /home/*/public_html"
    local suspicious_exts="pl sh py php rb exe"
    
    for dir in $suspicious_dirs; do
        for ext in $suspicious_exts; do
            local sus_files=$(find $dir -name "*.$ext" -type f -mtime -7 2>/dev/null)
            if [ -n "$sus_files" ]; then
                output "${YELLOW}在 $dir 目录发现近期 $ext 类型文件:${NC}"
                output "$sus_files"
                
                # 如果是脚本文件，检查内容中的关键字
                for file in $sus_files; do
                    if [ -f "$file" ]; then
                        local malicious_content=$(grep -l -E "socket|bind|shell|backdoor|remote_|download|exec|system|connect" "$file" 2>/dev/null)
                        if [ -n "$malicious_content" ]; then
                            output "${RED}警告: $file 文件包含可疑关键字:${NC}"
                            output "$(grep -E "socket|bind|shell|backdoor|remote_|download|exec|system|connect" "$file" | head -n 5)"
                        fi
                    fi
                done
            fi
        done
    done
    
    # 4. 检测伪装的系统进程
    output "\n${GREEN}----- 伪装系统进程检查 -----${NC}"
    local sys_procs="clock-applet systemd-network networkmanager httpd apache sshd crond ntpd"
    
    for proc in $sys_procs; do
        # 查找标准路径外的系统进程
        local fake_procs=$(ps -ef | grep "$proc" | grep -v grep | grep -v -E "/usr/(s)?bin|/bin|/sbin" 2>/dev/null)
        if [ -n "$fake_procs" ]; then
            output "${RED}警告: 可能是伪装的系统进程:${NC}"
            output "$fake_procs"
            
            # 检查这些进程的网络连接
            local pid=$(echo "$fake_procs" | awk '{print $2}' | head -n 1)
            if [ -n "$pid" ]; then
                output "进程 $pid 的网络连接:"
                output "$(lsof -i -n -P 2>/dev/null | grep "$pid")"
            fi
        fi
    done
    
    # 5. 检测可疑的cron任务
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 查找可疑的计划任务 ━━━━━━━━━━━━━━━━━━┓${NC}"
    for user in $(cut -f1 -d: /etc/passwd); do
        output "查询 $user 的计划任务:"
        crontab -u "$user" -l 2>/dev/null || echo "用户 $user 没有计划任务"
    done
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 查找登录脚本中的异常 ━━━━━━━━━━━━━━━━━━┓${NC}"
    for file in /etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/*.sh /etc/bash_completion.d/* ~/.bashrc ~/.bash_profile ~/.profile; do
        if [ -f "$file" ]; then
            output "检查 $file:"
            output "$(grep -l "wget\|curl\|echo\|Base64\|eval\|exec\|netcat\|whoami\|nc\|chmod\|chown\|useradd\|groupadd" "$file" 2>/dev/null)"
        fi
    done
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 检查计划任务异常 ━━━━━━━━━━━━━━━━━━┓${NC}"
    for crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        if [ -d "$crondir" ]; then
            output "检查 $crondir:"
            output "$(ls -la "$crondir" 2>/dev/null)"
        fi
    done
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 检查系统启动项 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "检查 /etc/rc.local:"
    if [ -f "/etc/rc.local" ]; then
        output "$(cat /etc/rc.local 2>/dev/null)"
    else
        output "/etc/rc.local 文件不存在"
    fi
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

# 主函数
main() {
    check_root
    init_output_file
    
    # 收集系统信息，减少命令执行次数
    collect_process_info
    
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${WHITE}           Linux 应急响应分析报告              ${BLUE}      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}分析主机:${NC} $(hostname)"
    echo -e "${YELLOW}开始时间:${NC} $(date)"
    echo -e "${YELLOW}执行用户:${NC} $(whoami)"
    echo -e "${YELLOW}分析版本:${NC} v4.0 高级分析\n"
    
    # 显示进度条
    progress_bar 0
    
    # 1. 系统基础信息
    header "系统基础信息"
    output "$(hostname)"
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 内核版本 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(uname -a)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 系统版本 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(cat /etc/*release 2>/dev/null)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 运行时间 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(uptime)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 系统资源 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(free -h)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${GREEN}┏━━━━━━━━━━━━━━ 磁盘使用情况 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(df -h)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    progress_bar 5
    
    # 2. 系统进程检查
    header "系统进程检查"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ CPU使用率TOP10 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(cat /tmp/er_ps_aux.tmp | sort -rn -k 3,3 | head -n 10)"
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ 内存使用率TOP10 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(cat /tmp/er_ps_aux.tmp | sort -rn -k 4,4 | head -n 10)"
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ 所有用户进程 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(cat /tmp/er_ps_ef.tmp | grep -v root)"
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ 隐藏进程检查 ━━━━━━━━━━━━━━━━━━┓${NC}"
    check_hidden_proc
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    progress_bar 15
    
    # 3. 网络连接
    header "网络连接"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 网络接口 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(ip addr 2>/dev/null || ifconfig -a)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 路由表 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(ip route 2>/dev/null || route -n)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ ARP表 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(ip neigh 2>/dev/null || arp -a)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 监听端口 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(netstat -tulpn 2>/dev/null || ss -tulpn)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 已建立连接 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(netstat -anp 2>/dev/null | grep ESTABLISHED || ss -anp | grep ESTAB)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    analyze_network_traffic
    progress_bar 30
    
    # 4. 用户检查
    header "用户检查"
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 当前活跃用户 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(who -a)"
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 登录用户历史 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(last | head -n 10)"
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 有效账户列表 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(cat /etc/passwd | grep -v nologin | grep -v false)"
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ Sudoers配置 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$")"
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 权限较高用户 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(grep -v -E "nologin|false" /etc/passwd | awk -F: '$3==0 || $4==0 {print $1}')"
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${YELLOW}┏━━━━━━━━━━━━━━━━━━ 检查SSH密钥 ━━━━━━━━━━━━━━━━━━┓${NC}"
    find_ssh_keys
    output "${YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    progress_bar 40
    
    # 5. 文件系统检查
    header "文件系统检查"
    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 临时目录可疑文件 ━━━━━━━━━━━━━━━━━━┓${NC}"
    check_tmp_files
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"

    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 敏感文件权限 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 合并检查SUID和SGID文件，减少find /命令执行次数
    output "SUID/SGID文件检查:"
    # 只搜索关键目录而不是整个文件系统
    find_targets="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"
    output "$(find $find_targets -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | sort)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"

    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 可写目录 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 只检查重要的系统目录
    sys_dirs="/etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /var/www"
    output "$(find $sys_dirs -type d -perm -2 -ls 2>/dev/null | grep -v "/\.[A-Za-z0-9]")"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"

    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 查找隐藏文件 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 缩小搜索范围到敏感目录
    hide_targets="/etc /var /opt /tmp /home /root /usr/bin /usr/sbin /bin /sbin"
    output "$(find $hide_targets -name ".*" -type f -not -path "*/\.*/*" 2>/dev/null | head -n 20)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"

    output "\n${GREEN}┏━━━━━━━━━━━━━━━━━━ 最近修改的文件 ━━━━━━━━━━━━━━━━━━┓${NC}"
    # 限制到重要目录
    recent_targets="/etc /bin /sbin /usr/bin /usr/sbin /var/www /tmp /var/tmp"
    output "$(find $recent_targets -type f -mtime -3 2>/dev/null | grep -v "/\.svn/" | head -n 20)"
    output "${GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    progress_bar 55
    
    # 6. 历史命令检查
    header "历史命令检查"
    output "${GREEN}----- Root历史命令 -----${NC}"
    output "$(tail -n 20 /root/.bash_history 2>/dev/null)"
    output "\n${GREEN}----- 其他用户历史命令 -----${NC}"
    for user in $(ls /home 2>/dev/null); do
        output "\n用户 $user:"
        output "$(tail -n 5 /home/$user/.bash_history 2>/dev/null)"
    done
    progress_bar 60
    
    # 7. 计划任务检查
    header "计划任务检查"
    output "${GREEN}----- 系统计划任务 -----${NC}"
    output "$(ls -la /etc/cron* 2>/dev/null)"
    output "\n$(cat /etc/crontab 2>/dev/null)"
    output "\n${GREEN}----- 用户计划任务 -----${NC}"
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab=$(crontab -u $user -l 2>/dev/null)
        if [ $? -eq 0 ]; then
            output "\n用户 $user:"
            output "$crontab"
        fi
    done
    output "\n${GREEN}----- 系统定时任务 -----${NC}"
    output "$(systemctl list-timers --all 2>/dev/null | head -n 10)"
    progress_bar 65
    
    # 8. 日志检查
    header "日志检查"
    output "\n${BLUE}┏━━━━━━━━━━━━━━━━━━ 系统启动日志异常 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(dmesg | grep -i 'fail\|error\|warn' | head -n 20)"
    output "${BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${BLUE}┏━━━━━━━━━━━━━━━━━━ 认证相关日志 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(grep -i 'fail\|invalid\|error\|warn' /var/log/auth.log 2>/dev/null | tail -n 20)"
    output "${BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${BLUE}┏━━━━━━━━━━━━━━━━━━ 系统日志异常 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(grep -i 'fail\|invalid\|error\|warn' /var/log/syslog 2>/dev/null | tail -n 20)"
    output "${BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${BLUE}┏━━━━━━━━━━━━━━━━━━ 安全相关日志 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(grep -i 'fail\|invalid\|error\|warn' /var/log/secure 2>/dev/null | tail -n 20)"
    output "${BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${BLUE}┏━━━━━━━━━━━━━━━━━━ 最近执行的命令 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(grep -i 'COMMAND=' /var/log/auth.log 2>/dev/null | tail -n 10)"
    output "${BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    progress_bar 70
    
    # 9. 恶意文件扫描
    header "恶意文件扫描"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 查找可疑定时任务 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "系统定时任务:"
    output "$(cat /etc/crontab 2>/dev/null)"
    output "\n用户定时任务:"
    output "$(for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 可疑启动脚本 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "/etc/init.d/ 目录内容:"
    output "$(ls -la /etc/init.d/ 2>/dev/null)"
    output "\n/etc/rc*.d/ 目录内容:"
    output "$(ls -la /etc/rc*.d/ 2>/dev/null | head -n 20)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 查找可疑系统服务 ━━━━━━━━━━━━━━━━━━┓${NC}"
    if command -v systemctl >/dev/null 2>&1; then
        output "$(systemctl list-units --type=service --state=running | head -n 20)"
    else
        output "$(service --status-all 2>/dev/null || echo '无法获取服务列表')"
    fi
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 查找恶意脚本文件 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(find /tmp /var/tmp /dev/shm -name "*.sh" -o -name "*.pl" -o -name "*.py" -o -name "*.php" 2>/dev/null | head -n 15)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ Web目录可疑文件 ━━━━━━━━━━━━━━━━━━┓${NC}"
    web_dirs="/var/www/html /usr/local/apache2/htdocs /usr/local/nginx/html /srv/www"
    for dir in $web_dirs; do
        if [ -d "$dir" ]; then
            output "$dir 目录中的可疑文件:"
            output "$(find $dir -type f -name "*.php" -mtime -7 2>/dev/null | head -n 10)"
        fi
    done
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 查找大型文件 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null | head -n 10)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 查找可疑隐藏文件 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(find / -name "*.enc" -o -name "*.crypted" -o -name "nmap*" -o -name "sqlmap*" -o -name "*.torrent" 2>/dev/null | head -n 15)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${PURPLE}┏━━━━━━━━━━━━━━━━━━ 检查恶意负载工具 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(find / -name "nc" -o -name "netcat" -o -name "john" -o -name "nikto" -o -name "hydra" 2>/dev/null | grep -v "documentation" | head -n 15)"
    output "${PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    progress_bar 85
    
    # 10. 网络流量分析
    header "网络流量分析"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ 已建立的连接 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(netstat -tuapn 2>/dev/null | grep ESTABLISHED | head -n 20 || ss -tuapn | grep ESTAB | head -n 20)"
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ 监听端口 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(netstat -tulpn 2>/dev/null | grep LISTEN | head -n 20 || ss -tulpn | grep LISTEN | head -n 20)"
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ 活跃网络连接 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(lsof -i 2>/dev/null | head -n 25 || echo '无法获取lsof信息')"
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ 网络接口 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(ip addr 2>/dev/null || ifconfig -a)"
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    output "\n${CYAN}┏━━━━━━━━━━━━━━━━━━ 路由表 ━━━━━━━━━━━━━━━━━━┓${NC}"
    output "$(ip route 2>/dev/null || route -n)"
    output "${CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
    progress_bar 92
    
    # 11. 安全设置检查
    header "安全设置检查"
    output "${GREEN}----- SSH配置 -----${NC}"
    output "$(grep -v "^#" /etc/ssh/sshd_config 2>/dev/null | grep -v "^$")"
    output "\n${GREEN}----- 防火墙状态 -----${NC}"
    if command -v ufw >/dev/null 2>&1; then
        output "$(ufw status 2>/dev/null)"
    elif command -v firewalld >/dev/null 2>&1; then
        output "$(firewall-cmd --list-all 2>/dev/null)"
    elif command -v iptables >/dev/null 2>&1; then
        output "$(iptables -L -n 2>/dev/null)"
    fi
    output "\n${GREEN}----- 内核参数 -----${NC}"
    output "$(sysctl -a 2>/dev/null | grep -E 'ipv4.ip_forward|ipv4.icmp_echo|kernel.hostname' 2>/dev/null)"
    progress_bar 70
    
    # 12. 内核模块检查
    header "内核模块检查"
    output "${GREEN}----- 已加载内核模块 -----${NC}"
    output "$(lsmod | head -n 20)"
    progress_bar 75
    
    # 13. 关键文件校验
    header "关键文件校验"
    output "${GREEN}----- 系统命令哈希 -----${NC}"
    for cmd in netstat ps ls ssh find grep iptables tcpdump; do
        if path=$(which $cmd 2>/dev/null); then
            output "$cmd: $(md5sum $path 2>/dev/null)"
        fi
    done
    output "\n${GREEN}----- 系统库文件检查 -----${NC}"
    output "$(ls -la /lib/systemd/system/*.service 2>/dev/null | grep -v '.wants' | head -n 10)"
    output "\n${GREEN}----- 启动项检查 -----${NC}"
    output "$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -n 15)"
    progress_bar 80
    
    # 14. 网络服务检查
    header "网络服务检查"
    output "${GREEN}----- 服务状态 -----${NC}"
    output "$(systemctl list-units --type=service --state=running | grep ".service" | head -n 20)"
    output "\n${GREEN}----- Web服务器检查 -----${NC}"
    if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        output "Apache运行状态:"
        output "$(systemctl status apache2 2>/dev/null || systemctl status httpd 2>/dev/null)"
    fi
    if command -v nginx >/dev/null 2>&1; then
        output "\nNginx运行状态:"
        output "$(systemctl status nginx 2>/dev/null)"
    fi
    progress_bar 85
    
    # 15. 新增功能：高级威胁检测
    check_advanced_threats
    progress_bar 88
    
    # 16. 新增功能：SSH日志安全分析
    analyze_ssh_logs
    progress_bar 90
    
    # 17. 网络流量分析
    analyze_network_traffic
    progress_bar 93
    
    # 18. Rootkit检测
    detect_rootkits
    progress_bar 96
    
    # 19. 系统安全基线检查
    security_baseline_check
    progress_bar 100
    
    echo ""
    
    divider
    output "${RED}检查完成！请重点关注：${NC}"
    output "${YELLOW}1. ${WHITE}异常的ESTABLISHED连接和未知端口${NC}"
    output "${YELLOW}2. ${WHITE}高CPU/内存占用进程${NC}"
    output "${YELLOW}3. ${WHITE}/tmp和/dev/shm目录可疑文件${NC}"
    output "${YELLOW}4. ${WHITE}特权用户变更和可登录账户${NC}"
    output "${YELLOW}5. ${WHITE}SUID/SGID文件和异常计划任务${NC}"
    output "${YELLOW}6. ${WHITE}安全日志中的失败登录尝试${NC}"
    output "${YELLOW}7. ${WHITE}异常网络连接和监听端口${NC}"
    output "${YELLOW}8. ${WHITE}Rootkit检测报告中的警告${NC}"
    output "${YELLOW}9. ${WHITE}SSH爆破记录和可疑登录${NC}"
    output "${YELLOW}10. ${WHITE}伪装系统进程和可疑文件检测结果${NC}"
    divider
    
    # 清理临时文件
    cleanup_temp_files
    
    if [ -n "$OUTPUT_FILE" ]; then
        echo "结果已保存到: $OUTPUT_FILE"
    fi
}

# 执行主函数
main
