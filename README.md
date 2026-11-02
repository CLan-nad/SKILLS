# SKILLS

个人维护的 Agent Skills 集合，按 `SKILL.md` 约定组织：frontmatter 里的 `name` / `description` 决定何时触发，主流程留在 `SKILL.md`，细则拆进 `references/` 按需读取。可直接放进 Codex、Claude Code 或其他兼容该格式的 agent。

两个 skill 都服务于 **Linux 操作系统安全**：一个打**系统配置面**，一个打**二进制代码面**，也可以串起来用——先用 `os-security` 摸出可疑的 SUID 二进制或 D-Bus 服务，再把二进制丢给 `ghidra-mcp-vuln-hunter` 逆调用链。

| Skill | 面向 | 典型场景 |
| --- | --- | --- |
| [`os-security`](os-security/SKILL.md) | Linux 主机与发行版组件 | SUID / Capabilities / D-Bus / PolicyKit / systemd / udev / cron / sudo 的越权与提权评估；分析现成扫描结果；审计 Kylin、openKylin 等系统配置 |
| [`ghidra-mcp-vuln-hunter`](ghidra-mcp-vuln-hunter/SKILL.md) | 用户态二进制 | D-Bus 服务、netlink、socket 服务端、配置解析、守护进程的接口梳理、调用链分析与漏洞确认 |

## 适用范围

- **目标平台：Linux**。攻击面、判定口径和利用手法都围绕 Linux 的机制展开：SUID / 文件 Capabilities、D-Bus（系统总线与会话总线、点对点与抽象套接字）、PolicyKit、systemd unit、udev、cron、sudoers、内核模块参数等。
- **发行版**：以 Kylin / openKylin / Ubuntu / Debian 系为主，其他使用 systemd + D-Bus + PolicyKit 的发行版同样适用；涉及厂商自研组件时按“自研优先”处理。
- **不覆盖**：Windows、macOS、Android、纯固件 / 裸机目标。`ghidra-mcp-vuln-hunter` 的逆向手段本身是通用的，但入口识别与攻击面梳理按 Linux 用户态程序（D-Bus 服务、netlink、socket 服务端、配置解析、守护进程）组织。

## os-security

黑盒优先：先换 uid 实测“普通用户能不能做原本要 root 的事”，再决定要不要看代码。核心约定：

- **判定靠实测**：权限文件只用于定位，结论以 `setpriv` 换 uid、`pkcheck`、marker + owner uid 等实测结果为准
- **不造 root**：需要特权时向使用者申请凭据，禁止用 docker / chroot / user namespace 冒充真实 root
- **不可逆动作不执行**：重启、格式化、回滚一律跳过；其余危害（含进程级 DoS）实测并报告
- **产出可复现**：`<目标>/vuln-00N/report.md` + `poc.py`，另附一份 `测试记录.md` 台账，记录每个攻击面“已测 / 跳过 + 原因”

主流程与红线见 [`os-security/SKILL.md`](os-security/SKILL.md)。

## ghidra-mcp-vuln-hunter

依赖 Ghidra MCP 后端（bridge + headless 容器），主流程：

```
⓪ 环境确认 → ① 程序概览 → ② 攻击面获取 → ③ 识别业务接口 → ④ 深入分析调用链 → ⑤ 漏洞确认 → ⑥ POC
```

目标有运行环境时，优先用 `busctl introspect` 等黑盒手段核对总线名、接口与方法签名，POC 必须端到端跑出观察物；只有二进制时退化为静态梳理，并标注“待在真实环境验证”。

后端部署见 [`docker/deployment.md`](ghidra-mcp-vuln-hunter/docker/deployment.md)。验证过的版本组合：镜像 `clannad1/ghidra-mcp-headless:7.0.0` ↔ bridge `7.0.0` ↔ Ghidra `12.1.2`。

## 安装

克隆后把 skill 目录复制或软链到 agent 的 skills 目录。

```bash
git clone https://github.com/CLan-nad/SKILLS.git
mkdir -p ~/.claude/skills
cp -r SKILLS/os-security SKILLS/ghidra-mcp-vuln-hunter ~/.claude/skills/
```

```powershell
git clone https://github.com/CLan-nad/SKILLS.git
New-Item -ItemType Directory -Force "$env:USERPROFILE\.codex\skills" | Out-Null
Copy-Item -Recurse SKILLS\os-security, SKILLS\ghidra-mcp-vuln-hunter "$env:USERPROFILE\.codex\skills\"
```

想跟着仓库更新，用软链代替复制（`ln -s "$PWD/SKILLS/os-security" ~/.claude/skills/os-security`），或定期 `git pull` 后重新复制。

## 目录结构

```
.
├── os-security/
│   ├── SKILL.md
│   └── references/
│       ├── component-discovery.md     攻击面梳理与门禁检查表
│       ├── suid-analysis.md           SUID 二进制分析
│       ├── cap-analysis.md            文件 Capabilities 分析
│       ├── dbus-authz.md              D-Bus 授权（含点对点 / 抽象套接字）
│       ├── polkit-authz.md            PolicyKit 策略审计
│       ├── exploit-patterns.md        深入利用手法
│       ├── report-template.md         报告与测试记录模板
│       ├── poc-template.py            PoC 四阶段骨架
│       ├── inj_sweep.py               批量注入探测
│       └── cvss31_calc.py             CVSS 3.1 复核
└── ghidra-mcp-vuln-hunter/
    ├── SKILL.md
    ├── docker/
    │   └── deployment.md              拓扑 / 镜像 / bridge / 故障排查
    └── references/
        ├── attack-surface.md          ② 攻击面获取
        ├── entry-point-recognition.md ③ 识别业务接口
        ├── call-chain-analysis.md     ④ 调用链分析
        └── vuln-patterns.md           ⑤ 漏洞模式
```

## 环境要求

| Skill | 需要 |
| --- | --- |
| os-security | Linux 目标机（普通用户立足点即可）；Python 3 跑 PoC；需要 root 的步骤会单独申请凭据 |
| ghidra-mcp-vuln-hunter | Docker；Ghidra MCP bridge；支持 MCP 的 agent 客户端 |

## 免责声明

仅用于自有系统或已获书面授权的目标。跑 PoC 前先确认授权范围；skill 里的红线（不可逆动作、不留后门、凭据不写入报告）请勿自行放宽。

仓库暂未附 LICENSE。
