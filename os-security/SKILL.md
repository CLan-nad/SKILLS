---
name: os-security
description: "Linux 系统黑盒漏洞挖掘：分析 SUID 文件、文件能力（Capabilities）、D-Bus 接口授权、PolicyKit 策略配置，评估风险并尝试未授权利用，生成 POC 和漏洞报告。Use when: (1) 用户需要对 Linux 系统进行黑盒安全评估和漏洞挖掘，(2) 用户提供了 SUID/文件能力/D-Bus/PolicyKit 扫描结果需要分析，(3) 用户需要生成授权不当类漏洞的 POC 和报告，(4) 需要对 Linux 系统进行本地提权/未授权访问测试，(5) 需要审计 Kylin/银河麒麟/openKylin 系统的安全配置。"
---

# OS Security — 操作系统黑盒漏洞挖掘

## 运行模型：Agent on Target

Agent 安装在目标系统上，所有命令通过 Bash 在目标系统本地执行。

---

## 前置检查

```bash
id && whoami && uname -a                          # 确认为普通用户，确认系统版本
which strings file getcap busctl pkaction nm readelf strace 2>/dev/null  # 确认工具可用
```

**规则**：禁止在用户工作目录下创建临时文件。临时文件一律用 `$TEMP` 或 `/tmp`，使用后清理。

---

## 核心判断原则

### 什么是漏洞

**普通用户能否通过 SUID/Cap/D-Bus/PolicyKit 执行原本需要 root 的操作？能 = 漏洞。**

判定流程（必须按顺序）：

| 步骤 | 问题 | 方法 |
|------|------|------|
| **0. 权限基线** | 普通用户默认能做吗？ | 直接执行该操作，观察是否需要认证。**必须先做。** |
| 1. 功能识别 | 这个二进制/策略/方法能做什么？ | `strings`、`strace`、`pkaction`、关键词映射 |
| 2. 可达性 | 普通用户能调用吗？ | 以普通用户身份执行，确认 `id` 非 root |
| 3. 影响验证 | 操作真的生效了吗？ | 系统级命令验证，不依赖返回值 |
| 4. 权限对比 | 绕过了本应存在的权限检查？ | 对比步骤 0 的基线 |

### 什么不是漏洞（拒绝标准）

任一条件满足 → 判定为非漏洞，停止测试：

1. **设计意图**：该操作本身就是为普通用户设计的
2. **默认权限**：普通用户不依赖任何提权机制即可执行
3. **操作拦截**：执行失败或无实际效果
4. **策略正确**：Polkit `modify.system` 配的是 `auth_admin`
5. **开源一致**：开源组件配置与上游未修改

**信息泄露专项**：读文件/接口返回信息 ≠ 信息泄露。先用 `cat`/`curl` 以普通用户直接试——本就 world-readable 的文件内容不是漏洞。

**Polkit 专项**：`modify.own` + `yes` = 正常。只有 `modify.system` + `yes` 才是漏洞。

### 优先级策略

**自研组件 > 开源组件**。kydima、ksaf、ukui、kysec、三权分立相关组件优先深挖。开源未修改的默认跳过。

---

## 入口识别与执行流程

### 识别入口类型

```
用户输入
  ├─ 组件名        → 模式 A：组件全流程
  ├─ 二进制路径     → 模式 B：二进制驱动
  ├─ D-Bus 服务名   → 模式 C：D-Bus 驱动
  ├─ PolicyKit action → 模式 D：PolicyKit 驱动
  └─ 配置文件路径    → 模式 E：配置文件驱动
```

### 前置步骤：执行组件

**不运行就测试等于白测。** 有 `.service` → `systemctl start`。有 `.ko` → `insmod`/`modprobe`。已在运行的检查状态即可。无法启动的记录原因，跳过运行时测试只测静态项。

### 门禁检查

每个攻击面先确认适用性，不适用则跳过：

| 攻击面 | 有意义的条件 | 不满足则 |
|--------|------------|---------|
| SUID/Cap | `find`/`getcap` 有输出 | 跳过 |
| D-Bus | 有 D-Bus 策略文件或用户指定了服务 | 跳过 |
| PolicyKit | 有 policy 文件或用户指定了 action | 跳过 |
| 系统状态 diff | 有 `.service` 或 `.ko` 且可启动 | 跳过 |
| sudo/cron/Unix socket | 对应命令有输出 | 跳过 |

### 模式 A：组件驱动

详见 [references/component-discovery.md](references/component-discovery.md)。

| 步骤 | 内容 |
|------|------|
| A0 | `rpm -ql` → 文件清单 |
| A1 | 组件分类（内核模块/守护进程/工具/配置/库）|
| A2 | 权限摸底（SUID/Cap/D-Bus/PolicyKit/配置）|
| A3 | 启服前后 diff（netlink/securityfs/D-Bus/socket）|
| A4 | 二进制分析（checksec/nm/strings/格式化字符串）|
| A5 | strace 按 syscall 分类跟踪 |
| A6 | 进入统一验证 |

### 模式 B：二进制驱动

详见 [references/suid-analysis.md](references/suid-analysis.md)。

| 步骤 | 内容 |
|------|------|
| B0 | 权限基线 |
| B1 | 基本属性（file/ls -la/rpm -qf）|
| B2 | 安全特性（checksec/readelf：CANARY/NX/PIE/RELRO）|
| B3 | 导入函数（nm -D：system/popen/exec/sprintf/strcpy）|
| B4 | 字符串分析（关键词 + 格式化字符串 + 文件路径）|
| B5 | strace 按 syscall 分类跟踪 |
| B6 | 进入统一验证 |

### 模式 C：D-Bus 驱动

详见 [references/dbus-authz.md](references/dbus-authz.md)。

| 步骤 | 内容 |
|------|------|
| C0 | 权限基线（XML Policy + PolicyKit action）|
| C1 | `busctl tree` + `busctl introspect` + `busctl status` |
| C2 | 关键词定级（P0-P3，详见 dbus-authz.md）|
| C3 | 普通用户 `busctl --system call` 调用 |
| C4 | 系统级命令验证 |
| C5 | 确认漏洞后，Python 深入利用（详见 deep-exploitation.md）|

### 模式 D：PolicyKit 驱动

详见 [references/polkit-authz.md](references/polkit-authz.md)。

| 步骤 | 内容 |
|------|------|
| D0 | `pkaction --verbose` 查 allow_active |
| D1 | 对比同服务其他 action |
| D2 | `pkexec` 或 D-Bus 无密码调用测试 |
| D3 | 系统级命令验证 |

### 模式 E：配置文件驱动

| 步骤 | 内容 |
|------|------|
| E0 | `ls -la`/`getfacl` 权限检查 |
| E1 | 查找可注入字段（路径、命令、ExecStart）|
| E2 | `ps`/`systemctl` 查关联进程 |
| E3 | 如可写，修改后观察系统行为 |

所有模式最终汇入统一验证和报告。

---

## 统一验证与报告

### 验证

发现风险项后：步骤 0 权限基线 → 风险定级 → 可达性验证 → 系统级影响验证 → POC。

POC 格式 —— SUID/能力（5 步）：

```bash
## [P0/P1] <路径> — <说明>

# 步骤0：权限基线
<普通用户执行> 2>&1  # 应失败或需要认证

# 步骤1：功能识别
strings <binary> | grep -iE '<关键词>'
file <binary>

# 步骤2：可达性
id  # 确认普通用户
<binary> <参数>

# 步骤3：系统级验证（不依赖返回值）
<系统级验证命令>

# 步骤4：权限对比
# 对比步骤0基线：是否绕过权限？
```

POC 格式 —— D-Bus/PolicyKit（4 步）：

```bash
## [P0/P1] <方法名> — <说明>

# 步骤0：权限基线
pkaction --action-id <action> --verbose | grep implicit

# 步骤1：接口枚举 + 功能识别
busctl introspect <服务> <路径>

# 步骤2：普通用户调用
busctl --system call <服务> <路径> <接口> <方法> <参数>

# 步骤3：系统级验证 + 恢复
<系统级验证命令>
<恢复命令>
```

D-Bus 深入利用（确认漏洞后）详见 [references/deep-exploitation.md](references/deep-exploitation.md)：白名单管控绕过（**遇到管控才绕，不上来就绕；LD_PRELOAD 优先**，bwrap/PYTHONPATH 限宽松服务，ptrace 替补）、任意文件写（SSH key/cron/systemd/sudoers.d/PAM）、路径穿越、提权链。

### 报告

按 [references/report-template.md](references/report-template.md) KVE 格式输出，CVSS 3.1 逐项写依据。

---

## 结论输出

### 目标不存在

```markdown
## 审计结论
- **目标**：<路径> → ❌ 不存在
- **系统**：<uname -a>
目标不存在，无法测试。建议确认路径或授权全量扫描。
```

### 未发现漏洞

```markdown
## 审计结论
- **目标**：<名称>  |  **模式**：<A-E>  |  **系统**：<uname -a>
- **审计范围**：<简述>
- **结论**：未发现漏洞。<逐项写原因>
> 如怀疑存在深层逻辑漏洞，可提供源码进一步分析。
```

### 发现漏洞

按 report-template.md 完整输出（KVE 编号 + 漏洞信息表 + 内部/外部概述 + 漏洞原因 + POC + 修复建议）。

---

## 测试过程记录

关键步骤写入 `<目标名>/test-log.md`：

```markdown
# 测试记录 — <目标名>
## 目标信息
## 门禁检查
| 攻击面 | 状态 |
## 关键步骤
### <攻击面>
`<命令>` → `<关键响应>`
→ 结论
```

原则：只记关键步骤、门禁跳过的写一行原因。

---

## 参考文件

| 文件 | 内容 |
|------|------|
| [references/component-discovery.md](references/component-discovery.md) | 组件信息收集、通信机制速查、系统状态对比、配置/sudo/cron/Unix socket 审计 |
| [references/suid-analysis.md](references/suid-analysis.md) | SUID 五步判定、二进制逆向（checksec/nm/strace）、GTFOBins、PATH 劫持 |
| [references/cap-analysis.md](references/cap-analysis.md) | 能力组合风险矩阵、麒麟组件分析、进程内代码执行注入（LD_PRELOAD / Qt 插件目录劫持） |
| [references/dbus-authz.md](references/dbus-authz.md) | D-Bus 方法关键词映射（P0-P3）、决策树、参数注入探测、白名单管控识别、验证命令 |
| [references/polkit-authz.md](references/polkit-authz.md) | PolicyKit allow_active 审计、pkexec 用法 |
| [references/deep-exploitation.md](references/deep-exploitation.md) | D-Bus 深入利用：白名单管控绕过四法（LD_PRELOAD 首选/bwrap/PYTHONPATH/ptrace）、任意文件写利用链、提权链 Python 模板、符号链接绕过 |
| [references/report-template.md](references/report-template.md) | KVE 报告模板、CVSS 3.1 严格评分指南、危害判定对照表 |

---

## 输出前自检

**所有模式**：
- [ ] 步骤 0 权限基线已完成
- [ ] 系统级命令验证，未依赖返回值
- [ ] CVSS 评分逐项有依据
- [ ] 测试范围未超出用户指定
- [ ] 门禁检查已执行，不适用项已标注原因
- [ ] 组件已执行后才做的运行时检查（D-Bus/端口/netlink）
- [ ] test-log.md 已记录关键步骤

**模式 A**：
- [ ] rpm -ql 文件清单完整，组件分类正确
- [ ] 系统状态 diff 已执行

**模式 B**：
- [ ] checksec / nm -D / strings（含格式化字符串）/ strace 四步已完成

**模式 C/D**：
- [ ] P0/P1 方法已标记并测试，陌生术语已查背景
- [ ] D-Bus 白名单管控：先确认受控（.limit/yaml + 报错分层）才评估绕过，LD_PRELOAD 优先，RootOnly 类直接放弃

**模式 E**：
- [ ] 权限和注入点已检查

**结论**：
- [ ] 有漏洞 → 完整 POC + CVSS 依据 + 修复建议
- [ ] 无漏洞 → 写清原因，不强挖，不自行扩大范围
- [ ] 目标不存在 → 已报告，未自行扩展扫描
