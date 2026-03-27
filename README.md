<p align="center">
  <h1 align="center">🛡️ CC-Check</h1>
  <p align="center">
    <strong>Claude Code 终端环境审计与加固工具</strong>
  </p>
  <p align="center">
    全自动化检测 · 100 分制量化评分 · 一键修复 · 跨平台支持
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue" alt="Platform">
    <img src="https://img.shields.io/badge/python-3.9+-green" alt="Python">
    <img src="https://img.shields.io/badge/tests-44%20passed-brightgreen" alt="Tests">
    <img src="https://img.shields.io/badge/score-100%20points-orange" alt="Score">
  </p>
</p>

---

## 📖 它是什么？

CC-Check 是一个面向 **Claude Code** 的终端环境审计工具。它通过 50+ 项自动化检测，识别你的终端环境中可能导致 API 风控（被 ban、限速、封号）的风险信号，并提供一键修复能力。

**核心场景：** 你使用 VPN + Clash Verge 做海外 API 开发（如 Anthropic Claude、OpenAI），但你的终端环境里可能残留着：
- 🔴 中国 ISP 的 DNS（114.114.114.114、223.5.5.5）
- 🔴 npm/pip 的中国镜像源（taobao、npmmirror）
- 🔴 时区/语言不匹配目标地区
- 🔴 IP 被识别为机房/VPN/代理（非住宅宽带）

这些信号会被 API 提供商的多维度风控模型捕获。CC-Check 帮你一次性发现并修复它们。

---

## ✨ 核心特性

### 🔍 11 组 50+ 项自动化检测

| 检测组 | 权重 | 检测内容 |
|--------|------|---------|
| **IP 质量** | 🔴 30/100 | 5 个权威渠道交叉验证（ipinfo / ip-api / proxycheck / bgpview / whois），识别伪住宅 IP |
| **DNS** | 15/100 | Google DNS whoami、Cloudflare DNS、系统 DNS 展示值（TUN 感知：TUN 开启时降级为 warn） |
| **系统** | 21/100 | 时区、语言、代理环境变量、输入法、主机名、度量单位、VS Code locale、字体指纹 |
| **网络** | 10/100 | 公网 IP 可达性、多源 IP 一致性、IPv6 泄露 |
| **Clash** | 8/100 | 进程检测、模式、TUN 开启、配置标记、DNS 守护 |
| **包管理器** | 6/100 | npm / pip / brew 中国镜像、GOPROXY、Docker daemon.json 镜像 |
| **隐私** | 6/100 | Claude 遥测目录、隐私环境变量、Shell 历史、SSH known\_hosts 中国 IP 扫描 |
| **Node.js** | 2/100 | 运行时时区和 locale 一致性 |
| **身份** | 1/100 | Git 全局身份、Git remote 中国托管扫描（gitee/coding.net） |
| **Claude** | 1/100 | Claude 设置语言 |
| **VPN** | 0（仅展示） | VPN 项目检测、单测、订阅生成、远端服务状态 |

### 📊 100 分制量化评分

```
╔════════════════════════════════════════════╗
║  CC-Check Score:  88 / 100  Grade: B    (88.4%)  ║
╠════════════════════════════════════════════╣
║  clash           8/8    ██████████  100.0%  ║
║  dns            15/15   ██████████  100.0%  ║
║  ip-quality     21/30   ███████░░░   70.0%  ║
║  network         9/10   █████████░   90.0%  ║
║  packages        6/6    ██████████  100.0%  ║
║  system         21/21   ██████████   98.6%  ║
╚════════════════════════════════════════════╝
```

### 🔧 一键修复

| 修复项 | 方法 |
|--------|------|
| Shell 环境变量（TZ/LANG/PROXY） | 自动更新 `.zprofile` / `.zshrc` / `.bashrc` |
| 系统 DNS（DHCP 防覆盖） | macOS: `networksetup` + `scutil` StaticDNS / Linux: `nmcli ignore-auto-dns` / Windows: `netsh static` |
| DNS 自动纠正 | macOS LaunchAgent / Linux systemd timer（每 15 秒检测并修复） |
| npm 中国镜像 | `npm config set registry https://registry.npmjs.org/` |
| pip 中国镜像 | 清除 `pip.conf` 中的 `index-url` |
| brew 中国镜像 | 清除 Shell profile 中的 `HOMEBREW_*` 变量 |
| Git 身份 | `git config --global --unset user.name/email` |
| Claude 遥测 | 删除 `~/.claude/telemetry/` |

所有修复命令支持 `--dry-run` 预览。

### 🌍 跨平台支持

| 能力 | macOS | Linux | Windows |
|------|-------|-------|---------|
| 全维度检测 | ✅ 完整 | ✅ 完整 | ✅ 核心项完整 |
| DNS 根治（DHCP 防覆盖） | ✅ `networksetup` + `scutil` | ✅ `nmcli` + `ignore-auto-dns` | ✅ `netsh static` |
| DNS 自动守护 | ✅ LaunchAgent 15s | ✅ systemd timer 15s | ❌ |
| Shell 环境修复 | ✅ zsh/bash/fish | ✅ bash/zsh/fish | ✅ PowerShell |
| 包管理器修复 | ✅ npm/pip/brew | ✅ npm/pip/brew | ✅ npm/pip |

> Windows 说明：`node / npm / pip / git` 相关检测与修复现在走原生命令调用，不再依赖类 Unix 的引号、重定向或 `find|grep` 组合，因此在 PowerShell / pwsh 环境下结果更稳定。  
> 某些 DNS whoami 检查仍可能受本机外部工具可用性影响，这类项会按当前实现返回 `warn/fail/skip`。

---

## 🚀 快速开始

### 安装

```bash
git clone https://github.com/Hsiangpo/CC-check.git
cd CC-check
```

无需额外依赖，纯 Python 3.9+ 标准库运行。远端 VPN 检查需要 `paramiko`：

```bash
python -m pip install paramiko  # 仅 VPN 远端检查需要，可选
```

### 基本用法

```bash
# 1. 全面审计（推荐）
python scripts/cc_check.py inspect

# 2. JSON 输出（便于自动化）
python scripts/cc_check.py inspect --json

# 3. 预览修复（不实际执行）
python scripts/cc_check.py fix-local --dry-run

# 4. 执行修复
python scripts/cc_check.py fix-local

# 5. 完整闭环：检测 → 修复 → 验证
python scripts/cc_check.py full

# 6. 自定义目标参数
python scripts/cc_check.py inspect \
  --target-timezone America/Los_Angeles \
  --target-locale en_US.UTF-8 \
  --proxy-url http://127.0.0.1:7897 \
  --expected-ip-type residential
```

### 作为 LLM Agent Skill 使用

CC-Check 同时也是 Codex / Claude Code / Gemini CLI 的 skill：

```
# 在 LLM Agent 中直接使用
> 帮我检查一下终端环境
> 修复 DNS 泄露
> 跑一轮完整的环境审计
```

---

## 🏗️ 项目结构

```
cc-check/
├── SKILL.md                      # LLM Agent skill 配置文件
├── README.md                     # 本文件
├── agents/
│   └── openai.yaml               # OpenAI agent 接口配置
├── references/
│   ├── check-matrix.md           # 审计矩阵（40+ 检测项详表）
│   └── rationale.md              # 设计决策与修复逻辑说明
├── scripts/
│   ├── cc_check.py               # 🎯 主编排器 & CLI 入口
│   ├── ip_quality.py             # 🌐 多渠道 IP 纯净度评估
│   ├── platform_ops.py           # 💻 跨平台操作抽象层
│   ├── scoring.py                # 📊 100 分制评分系统
│   └── vpn_adapter.py            # 🔌 VPN 项目适配层
└── tests/
    └── test_cc_check.py          # ✅ 40 个单元测试
```

### 模块职责

| 模块 | 行数 | 职责 |
|------|------|------|
| `cc_check.py` | ~1100 | CLI 解析、审计流程编排、修复逻辑、结果输出 |
| `platform_ops.py` | ~1500 | 跨平台抽象：DNS / TUN / 进程 / 输入法 / 静态 DNS / 字体指纹 等 |
| `vpn_adapter.py` | ~300 | VPN 项目检测与修复，适配器模式隔离特定项目结构 |
| `ip_quality.py` | ~230 | 5 渠道 IP 类型 / 风险 / ISP 交叉验证 |
| `scoring.py` | ~180 | 权重定义、评分计算、可视化报告生成 |
| `browser_leaks.py` | ~100 | 浏览器泄露检测 |

---

## 🎯 IP 质量检测详解

这是 CC-Check 最核心的检测项（占总分 30%）。通过 5 个独立权威渠道交叉验证：

| 渠道 | 提供信息 | 优势 |
|------|---------|------|
| **ipinfo.io** | 地理位置 + ASN + 运营商 | 最准确的地理定位 |
| **ip-api.com** | proxy / hosting / mobile 标记 | 最可靠的类型判断 |
| **proxycheck.io** | VPN 检测 + 风险评分 + 类型 | 最精细的风险量化 |
| **bgpview.io** | BGP 前缀 + RIR 分配信息 | ASN 级别验证 |
| **whois** | 注册国家 + 网络块信息 | 独立交叉验证 |

### 伪住宅 IP 检测

CC-Check 能识别 IDC 隧道包装的"伪住宅"IP（这类 IP 在 IP 提供商标注为 residential，但实际由数据中心中转）：

- ASN 不在已知住宅 ISP 白名单中（Comcast、AT&T、Verizon 等）
- `proxycheck.io` 返回类型 ≠ residential
- 风险评分 > 66/100

检测到伪住宅 IP 时会建议更换为真实家宽节点。

---

## 🔒 安全设计

| 安全措施 | 说明 |
|---------|------|
| **零硬编码凭据** | 所有路径通过 `Path.home()` 动态推导 |
| **输出脱敏** | `redact_text()` 过滤 SSH 密码、订阅链接等敏感值 |
| **无 Shell 注入** | VPN 适配器使用 `subprocess.run(cwd=)` 代替字符串拼接 |
| **--dry-run 保护** | 所有修复命令支持预览模式 |
| **不自动修复高风险项** | 系统语言、输入法、hosts 文件等不会被自动修改 |

---

## 📝 评分等级

| 等级 | 分数 | 含义 |
|------|------|------|
| **A+** | ≥ 95 | 生产安全，环境完全对齐 |
| **A** | ≥ 90 | 仅有轻微外观问题 |
| **B** | ≥ 80 | 可接受，存在已知 warn |
| **C** | ≥ 70 | 存在显著缺口 |
| **D** | ≥ 60 | 需要关注的失败项 |
| **F** | < 60 | 检测到关键风险 |

---

## 🧪 测试

```bash
# 运行全部 44 个单元测试
python -m unittest discover -s tests -p test_cc_check.py -v

# 测试覆盖
# - scoring.py: 权重完整性、评分计算、等级边界、报告格式
# - ip_quality.py: 类型常量、whois 解析、国家映射
# - platform_ops.py: 平台常量、系统信息获取、脚本生成
```

---

## 📋 不会自动修复的项（设计如此）

| 检测项 | 原因 |
|--------|------|
| 中文输入法 | 属于个人偏好，双语用户合理使用 |
| 系统语言 | 全局修改风险过高 |
| 度量单位 / 时间格式 | 系统级设置，不适合自动改 |
| Shell 历史 | 历史数据，不应删除 |
| /etc/hosts | 修改风险较高 |
| Cloudflare Asia PoP | 不等同于中国 ISP，不是泄露 |

---

## 🤝 贡献

欢迎 PR 和 Issue！以下方向特别欢迎贡献：

- 🐧 Linux 新发行版的修复逻辑验证
- 🪟 Windows 修复分支的实际环境验证
- 🔌 新 VPN 项目的适配器（在 `vpn_adapter.py` 中扩展）
- 🌐 新 IP 质量检测渠道集成

---

## 📄 许可证

MIT License

---

<p align="center">
  <sub>由 <a href="https://github.com/Hsiangpo">@Hsiangpo</a> 构建，经过五轮迭代打磨的生产级终端环境审计工具。</sub>
</p>
