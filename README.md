# Linux测评工具

## 项目简介
这是一个用于Linux系统等级保护测评的自动化检查工具。该工具可以帮助系统管理员和安全审计人员快速评估Linux系统的安全状况，检查是否符合等级保护要求。

## 主要功能

### 1. 身份鉴别
- 密码复杂度策略检查
- 密码有效期检查
- 空密码账户检查

### 2. 访问控制
- 特权账户检查
- 文件权限检查
- SUID文件检查

### 3. 安全审计
- 审计系统状态检查
- 日志完整性检查
- 审计规则检查

### 4. 入侵防范
- 防火墙状态检查
- 开放端口检查
- 敏感端口监控

### 5. 数据安全
- 磁盘加密检查
- 重要目录备份检查
- 文件权限检查

### 6. 数据库安全
- MySQL安全检查
- Redis安全检查
- 数据库配置审计

### 7. Web服务安全
- Web服务器配置检查
- SSL证书检查
- Web漏洞扫描

### 8. 容器安全
- Docker安全检查
- Kubernetes集群检查
- 容器镜像检查

### 9. 网络安全
- 网络接口检查
- 路由表检查
- IP地址范围检查

### 10. 漏洞扫描
- 系统漏洞扫描
- Web应用漏洞扫描
- 系统安全审计

## 使用方法

### 1. 环境要求
- Linux操作系统
- Root权限
- 基础工具包（netstat, ss, ip, ps, grep, awk, find）

### 2. 安装依赖 
```bash
CentOS/RHEL
sudo yum install -y net-tools iproute2 procps-ng grep gawk findutils
Ubuntu/Debian
sudo apt install -y net-tools iproute2 procps grep gawk findutils
```

### 3. 配置文件
1. 复制配置文件模板：
```bash
cp config.conf.example config.conf
```

2. 编辑配置文件：
```bash
vi config.conf
```
### 4. 运行脚本
```bash
sudo chmod +x grade_protection_complete.sh
sudo ./grade_protection_complete.sh
```

### 5. 查看报告
脚本执行完成后，将在 `grade_protection_results_时间戳` 目录下生成以下报告：
- grade_protection_report.txt（文本报告）
- grade_protection_report.html（HTML报告）
- grade_protection_report.pdf（PDF报告，需要安装wkhtmltopdf）

## 注意事项
1. 请确保以root权限运行脚本
2. 首次运行前请仔细检查配置文件
3. 部分功能需要安装额外的工具包
4. 扫描可能会对系统性能造成影响，建议在非高峰期执行

## 可选工具包
```bash
CentOS/RHEL
sudo yum install -y mysql-server redis docker-ce kubernetes-client apache2 lynis nikto nmap cryptsetup audit firewalld
Ubuntu/Debian
sudo apt install -y mysql-server redis-tools docker.io kubectl apache2 lynis nikto nmap cryptsetup auditd ufw
```

## 免责声明
本工具仅用于安全检查和等级保护测评，禁止用于未授权的安全测试或攻击行为。使用本工具进行测试时可能会影响系统性能或服务可用性，请在使用前充分评估风险。对于因使用本工具而造成的任何直接或间接损失，作者不承担任何责任。在使用本工具前，请确保您已获得必要的授权和许可。
