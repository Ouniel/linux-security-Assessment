# 🛡️ Linux安全应急响应检查脚本 v4.1

<div align="center">

![Version](https://img.shields.io/badge/version-4.1-blue.svg)
![Language](https://img.shields.io/badge/language-Bash-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen.svg)

**🔍 全面的Linux系统安全检测工具，快速识别入侵痕迹和安全漏洞**

[📋 功能特性](#-主要功能) • [🚀 快速开始](#-快速开始) • [📖 使用指南](#-使用方法) • [📝 更新日志](#-版本更新日志) • [🤝 贡献](#-贡献指南)

</div>

---

## 📊 简介

**Linux安全应急响应检查脚本**是一个专业的系统安全检测工具，旨在帮助安全人员在应急响应过程中快速发现Linux系统的安全问题和潜在威胁。通过全面收集和分析系统信息，该脚本能够有效识别入侵痕迹、系统漏洞和异常行为。

### ✨ v4.1 重大更新

> 🎯 **全新增加**：监控**17个关键Linux日志文件**的深度分析功能  
> 📊 包含系统核心日志、用户认证日志、服务应用日志、安全审计日志等的全面检测

---

## 🎯 主要功能

<details open>
<summary>🖱️ 点击展开/收起功能列表</summary>

### 🔧 系统分析
- 🖥️ **系统基础信息收集**：内核版本、系统版本、运行时间、系统资源等
- ⚙️ **进程检查**：CPU/内存使用率TOP分析、隐藏进程检测
- 🌐 **网络连接分析**：监听端口、已建立连接、网络接口配置等
- 👥 **用户账户检查**：活跃用户、登录历史、权限异常用户检测

### 🗂️ 文件系统
- 📁 **文件系统检查**：可疑文件检测、SUID/SGID文件、敏感目录权限
- 📜 **历史命令检查**：用户历史命令分析
- ⏰ **计划任务检查**：系统和用户计划任务异常检测

### 📋 日志监控
- 📊 **关键日志文件监控**：监控17个关键Linux日志文件，包括：
  - 🏗️ **系统核心日志**：`syslog`、`messages`
  - 🔐 **用户认证日志**：`auth.log`、`secure`
  - 🧠 **内核事件日志**：`kern.log`
  - 📈 **登录历史记录**：`wtmp`、`btmp`、`lastlog`
  - 🔄 **服务应用日志**：`cron`、`boot.log`、`dmesg`
  - 🌐 **Web服务器日志**：Apache/Nginx访问和错误日志
  - 🛡️ **安全审计日志**：`audit.log`、`faillog`
  - 📦 **包管理日志**：`dpkg.log`、`yum.log`

### 🔒 安全检测
- 🚨 **恶意文件扫描**：查找可疑脚本、Webshell等恶意文件
- 🎯 **高级威胁检测**：异常外部连接、伪装系统进程等
- 🔑 **SSH日志安全分析**：SSH爆破检测、可疑登录分析
- 👻 **Rootkit检测**：隐藏进程、隐藏端口、可疑内核模块检测
- ✅ **系统安全基线检查**：密码策略、SSH配置、文件权限等安全基线检查

</details>

---

## 🚀 快速开始

### 🎯 一键运行（推荐）
```bash
# 🌐 下载并运行脚本
curl -sSL https://raw.githubusercontent.com/Ouniel/linux-security-check/main/linux.sh | sudo bash
```

### 💻 本地运行
```bash
# 1️⃣ 下载脚本
wget https://raw.githubusercontent.com/Ouniel/linux-security-check/main/linux.sh

# 2️⃣ 添加执行权限
chmod +x linux.sh

# 3️⃣ 运行检查
sudo ./linux.sh

# 4️⃣ 保存结果到文件
sudo ./linux.sh -o security_report_$(date +%Y%m%d_%H%M%S).txt
```

---

## 📖 使用方法

### 🔧 基本用法

```bash
bash linux.sh
```

### 💾 将结果保存到文件

```bash
bash linux.sh -o 安全检查报告.txt
```

### ❓ 查看帮助信息

```bash
bash linux.sh -h
```

### 💡 实用示例

<details>
<summary>🖱️ 点击查看更多示例</summary>

```bash
# 📊 生成带时间戳的报告
sudo ./linux.sh -o "security_report_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"

# 📺 同时在屏幕显示和保存到文件
sudo ./linux.sh -o security_report.txt | tee console_output.log

# 📄 只保存关键结果（过滤颜色代码）
sudo ./linux.sh | sed 's/\x1b\[[0-9;]*m//g' > clean_report.txt
```

</details>

### 📋 参数说明

| 参数 | 描述 |
|------|------|
| `-o <文件>` | 📂 将检查结果保存到指定文件 |
| `-h` | ❓ 显示帮助信息 |

---

## 🔧 系统要求

<div align="center">

| 要求 | 说明 |
|------|------|
| 🐚 **Shell环境** | Bash shell |
| 👑 **运行权限** | Root权限 |
| 🐧 **操作系统** | Linux发行版（Debian/Ubuntu/CentOS/RHEL等） |
| 🛠️ **系统工具** | ps, netstat/ss, ip/ifconfig, find等 |

</div>

---

## 📝 安装方法

### 📥 方法一：直接下载
```bash
# 1️⃣ 下载脚本文件到本地
wget https://your-domain.com/linux.sh

# 2️⃣ 添加执行权限
chmod +x linux.sh

# 3️⃣ 以root权限运行
sudo ./linux.sh
```

### 🔄 方法二：克隆仓库
```bash
# 1️⃣ 克隆仓库
git clone https://github.com/your-username/linux-security-check.git
cd linux-security-check

# 2️⃣ 运行脚本
sudo ./linux.sh
```

---

## 📊 输出说明

脚本输出分为**14个主要检查模块**，每部分包含特定类型的安全检查结果：

<details>
<summary>🖱️ 点击查看详细输出说明</summary>

| 序号 | 模块名称 | 检查内容 |
|------|----------|----------|
| 1️⃣ | **系统基础信息** | 系统和内核版本信息 |
| 2️⃣ | **系统进程检查** | 异常进程、资源占用分析 |
| 3️⃣ | **网络连接** | 网络接口、路由表、ARP表等 |
| 4️⃣ | **用户检查** | 用户账户和权限分析 |
| 5️⃣ | **文件系统检查** | 敏感文件、异常权限分析 |
| 6️⃣ | **历史命令检查** | 用户执行的历史命令 |
| 7️⃣ | **计划任务检查** | 异常计划任务检测 |
| 8️⃣ | **日志检查** | 系统各类日志分析 |
| 9️⃣ | **恶意文件扫描** | 可疑文件检测 |
| 🔟 | **高级威胁检测** | 深度分析系统异常 |
| 1️⃣1️⃣ | **关键日志文件监控** | 17个核心日志文件的全面分析和异常检测 |
| 1️⃣2️⃣ | **SSH安全分析** | SSH爆破攻击检测和登录异常分析 |
| 1️⃣3️⃣ | **Rootkit检测** | 系统级隐藏威胁检测 |
| 1️⃣4️⃣ | **安全基线检查** | 系统安全配置合规性检查 |

</details>

---

## 📅 版本更新日志

### 🎉 v4.1 (2025-06-25)
<details open>
<summary><strong>🆕 新增功能：17个关键Linux日志文件监控</strong></summary>

#### ✅ 核心功能
- 🎯 新增 `monitor_critical_logs()` 函数，提供全面的日志文件监控和分析
- 📋 支持**17个关键日志文件**的存在性检查和异常检测：

#### 📊 监控的日志类别
- 🏗️ **系统核心日志**：`/var/log/syslog`、`/var/log/messages`
- 🔐 **用户认证日志**：`/var/log/auth.log`、`/var/log/secure`
- 🧠 **内核和系统日志**：`/var/log/kern.log`、`/var/log/boot.log`、`/var/log/dmesg`
- 📈 **登录监控日志**：`/var/log/wtmp`、`/var/log/btmp`、`/var/log/lastlog`
- 🔄 **服务应用日志**：`/var/log/cron`
- 🌐 **Web服务器日志**：Apache和Nginx的访问/错误日志
- 🛡️ **安全审计日志**：`/var/log/audit/audit.log`、`/var/log/faillog`
- 📦 **包管理日志**：`/var/log/dpkg.log`、`/var/log/yum.log`

#### 🔍 检测能力
- 🚨 智能检测系统错误、磁盘空间警告、服务事件
- 🔒 暴力破解攻击检测和IP统计分析
- 🌐 Web服务器可疑请求检测（包含恶意payload检测）
- 🛡️ 审计服务状态检查和失败系统调用分析
- 📦 软件包变更监控和今日操作统计
- 🔄 日志轮转配置检查
- ⚡ 风险评级系统（低/中/高）和安全建议
- 🔧 支持多发行版兼容性（Debian/Ubuntu/RHEL/CentOS）

</details>

### 🎯 v4.0 (之前版本)
<details>
<summary><strong>🔧 基础安全检查功能</strong></summary>

- ✅ 系统基础信息收集（内核版本、系统版本、运行时间等）
- ✅ 进程检查（CPU/内存使用率分析、隐藏进程检测）
- ✅ 网络连接分析（监听端口、已建立连接、网络接口等）
- ✅ 用户账户检查（活跃用户、登录历史、权限异常检测）
- ✅ 文件系统检查（SUID/SGID文件、敏感目录权限）
- ✅ 历史命令检查和计划任务检查
- ✅ SSH日志安全分析（SSH爆破检测、可疑登录分析）
- ✅ 高级威胁检测（异常外部连接、伪装系统进程）
- ✅ Rootkit检测（隐藏进程、隐藏端口、可疑内核模块）
- ✅ 系统安全基线检查（密码策略、SSH配置、文件权限）
- ✅ 网络流量分析和恶意文件扫描
- ✅ 彩色输出和进度条显示
- ✅ 结果导出功能

</details>

---

## 🚨 注意事项

> ⚠️ **重要提醒**

- 🔑 **权限要求**：此脚本需要以**root权限**运行以获取完整的系统信息
- 🖥️ **系统资源**：脚本运行时可能会消耗较多系统资源，建议在系统负载较低时执行
- 🔍 **结果判断**：输出结果仅供参考，需安全专业人员进一步分析判断
- 🛠️ **命令依赖**：某些检查项依赖特定命令，如这些命令不存在可能会跳过相关检查

---

## 📋 开发计划和未来版本

### 🔄 计划中的功能 (v4.2)
- 🔄 **实时威胁监控**：持续监控模式，实时检测异常
- 🔔 **智能告警系统**：基于威胁等级的自动告警
- 💾 **数据库取证**：MySQL/PostgreSQL等数据库安全检查
- 🐳 **容器安全检测**：Docker容器和镜像安全扫描
- 🔍 **恶意软件哈希检测**：已知恶意文件哈希比对
- 📊 **网络行为分析**：深度包检测和流量异常分析

### 📋 计划中的功能 (v4.3+)
- 📋 **合规性检查**：CIS基准、NIST框架合规性检测
- 🔧 **自动修复建议**：提供针对发现问题的自动修复脚本
- 🔗 **集成SIEM**：与主流SIEM系统集成
- 📱 **移动端监控**：支持Android设备安全检查
- ☁️ **云平台扩展**：AWS/Azure/GCP云环境安全检查
- 🤖 **机器学习检测**：基于ML的异常行为检测

### 🤝 贡献方式
- 🐛 **问题报告**：发现bug或提出改进建议
- 💡 **功能请求**：提出新功能需求
- 🔧 **代码贡献**：提交代码改进或新功能
- 📖 **文档改进**：完善使用文档和注释
- 🧪 **测试反馈**：在不同环境下测试并反馈结果

---

## 🤝 贡献指南

**欢迎提交问题报告和改进建议！** 请遵循以下贡献流程：

```bash
# 1️⃣ Fork本仓库
git fork https://github.com/Ouniel/linux-security-check.git

# 2️⃣ 创建feature分支
git checkout -b feature/amazing-feature

# 3️⃣ 提交您的更改
git commit -m 'Add amazing feature'

# 4️⃣ 推送到分支
git push origin feature/amazing-feature

# 5️⃣ 创建Pull Request
# 访问GitHub仓库页面创建PR
```

### 🎯 贡献准则
- 📝 **代码风格**：遵循现有的代码风格和命名规范
- 🧪 **测试覆盖**：确保新功能有适当的测试
- 📖 **文档更新**：更新相关文档和注释
- 🔍 **代码审查**：接受代码审查和反馈

---

## 📄 授权许可

本项目采用 **MIT License** 许可证，详见 [LICENSE](LICENSE) 文件。

---

## ⚠️ 免责声明

<details>
<summary>🖱️ 点击查看免责声明</summary>

1. 🎯 **使用目的**：本脚本仅用于安全检查和应急响应，请勿用于非授权的安全测试或任何非法用途。

2. 🖥️ **系统影响**：使用本脚本进行系统检查时可能会消耗系统资源，在生产环境中使用前请充分测试并评估影响。

3. 🔍 **结果准确性**：脚本检测结果仅供参考，不对所有安全问题提供完整覆盖，用户仍需专业安全人员进行综合分析和判断。

4. 📋 **责任限制**：开发者不对因使用本脚本而导致的任何直接或间接损失负责，包括但不限于数据丢失、系统中断或安全事件。

5. ✅ **使用协议**：使用本脚本表示您已阅读并接受本免责声明的所有条款。

</details>

---

<div align="center">

**🌟 如果这个项目对您有帮助，请给我们一个Star！🌟**

[![GitHub Stars](https://img.shields.io/github/stars/Ouniel/linux-security-Assessment?style=social)](https://github.com/your-username/linux-security-check/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Ouniel/linux-security-Assessment?style=social)](https://github.com/your-username/linux-security-check/network/members)

**感谢您的支持！💖**

---


</div>
