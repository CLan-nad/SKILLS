---
name: os-security
description: "Linux 系统黑盒漏洞挖掘：分析 SUID 文件、文件能力（Capabilities）、D-Bus 接口授权（含点对点 / 抽象套接字跨用户越权）、PolicyKit 策略配置，评估风险并尝试未授权利用，生成 POC 和漏洞报告。Use when: (1) 用户需要对 Linux 系统进行黑盒安全评估和漏洞挖掘，(2) 用户提供了 SUID/文件能力/D-Bus/抽象套接字/PolicyKit 扫描结果需要分析，(3) 用户需要生成授权不当类漏洞的 POC 和报告，(4) 需要对 Linux 系统进行本地提权/未授权访问测试，(5) 需要审计 Kylin/银河麒麟/openKylin 系统的安全配置。"
---

# OS Security — 操作系统黑盒漏洞挖掘

## 运行模型：Agent on Target

Agent 安装在目标系统上，所有命令通过 Bash 在目标系统本地执行。

---

## 前置检查

```bash
id && whoami && uname -a                          # 确认为普通用户，确认系统版本
which strings file getcap busctl pkaction nm readelf strace ss 2>/dev/null  # 确认工具可用
```

**规则**：禁止在用户工作目录下创建临时文件。临时文件一律用 `$TEMP` 或 `/tmp`，使用后清理。

## 开工三条（先默读再动手）

1. **次序**：枚举 → **参数注入首扫** → 系统级验证 → 静态仅兜底。**首扫未完成前，禁止进入反汇编。**
2. **判定靠黑盒**：是否注入、是否经 shell，以 marker + owner uid 为准；逆向（objdump/nm/strings）只用来**定位**，不用来**判定**。
3. **非破坏 + 非交互**：破坏性方法（reboot/restore/rm -rf）标"可达但不执行"；基线/对照一律非交互（勿用会弹密码的命令）。收尾跑「输出前自检」。

---

## 核心判断原则

### 什么是漏洞

**普通用户能否通过 SUID/Cap/D-Bus/PolicyKit 执行原本需要 root 的操作？能 = 漏洞。**

判定流程（必须按顺序）：

| 步骤 | 问题 | 方法 |
|------|------|------|
| **0. 权限基线** | 普通用户默认能做吗？ | 直接执行该操作，观察是否需要认证（**非交互**，勿用会弹密码的命令）。**必须先做。** |
| 1. 功能识别 | 这个二进制/策略/方法能做什么？ | `strings`、`strace`、`pkaction`、关键词映射 |
| 2. 可达性 | 普通用户能调用吗？ | **动态**：以普通用户身份执行，确认 `id` 非 root |
| 2.5 **参数注入首扫** | 字符串参数能否注入命令/SQL/路径？ | 对每个 `s/as/a{sv}` 参数打一轮载荷（marker + owner uid），**先于任何静态逆向**（见 dbus-authz.md「参数注入首扫」）|
| 3. 影响验证 | 操作真的生效了吗？ | 系统级命令验证，不依赖返回值 |
| 3.5 静态解释（可选） | 为什么会/不会这样？ | 入口→…→sink 全引用形式回溯（**仅当首扫无果或需解释时**，见「可达性回溯：疑似 sink → 攻击者入口」）|
| 4. 权限对比 | 绕过了本应存在的权限检查？ | 对比步骤 0 的基线 |

### 什么不是漏洞（拒绝标准）

任一条件满足 → 判定为非漏洞，停止测试：

1. **设计意图**：该操作本身就是为普通用户设计的
2. **默认权限**：普通用户不依赖任何提权机制即可执行
3. **操作拦截**：执行失败或无实际效果
4. **策略正确**：Polkit `modify.system` 配的是 `auth_admin`
5. **开源一致**：开源组件配置与上游未修改

**信息泄露专项（三分类，不得静默丢弃）**：先以 `cat`/`curl` 普通用户直接试，再按内容分类判定：

- **A 设计公开**（版本/帮助/公共配置等本就面向所有用户的内容）→ **非漏洞**，但须在报告/记录写一行"已评估、非漏洞（设计公开）"，不得省略。
- **B 敏感过度开放**（组件**私有数据目录**内文件 + **全局可读**（`-o=r`）+ 含用户名/UUID/路径/操作时间线/凭据/密钥等敏感内容）→ **独立低危编号**（CWE-732 权限配置不当 / CWE-200 信息暴露），等级按内容敏感度取（默认低危，含凭据/密钥则上调）。
- **C 使能器**（泄露数据是**另一漏洞的必要输入**，如泄露的还原点 UUID 可触发无鉴权还原）→ 仍按 B 独立编号，并**交叉引用**所使能的漏洞、上调其优先级。

> 可读性本身不构成越权（普通用户本就能 `cat`），故 B/C **不计为越权漏洞**，但**必须编号留痕**——禁止因"world-readable 即丢弃"而漏报。

**Polkit 专项**：`modify.own` + `yes` = 正常。只有 `modify.system` + `yes` 才是漏洞。

### 可选扩展模式：同权限域缺陷（插拔，默认关闭）

上述拒绝标准按**权限边界**判定：只有"普通用户绕过权限检查、执行原本需要 root 的操作"才算漏洞。这对**非特权目标**（以登录用户运行、无 SUID/Cap、无特权总线服务）会让全部缺陷落空。

为按需扩大产出，提供**插拔式扩展模式**——默认不启用，探测到非特权目标时由用户决定：

**触发门控**（权限摸底后判定；模式 A 的 A2 / 模式 B 的 B0 / 模式 D 的 D0）：

- `非特权实体` = 无 SUID/SGID + 无 capabilities + 以登录用户（非 root）运行 + 无 root 守护进程/系统总线特权服务（或特权方法均要求认证）
- **先完成全部特权面测试**；当剩余/全部攻击面都落在登录用户权限域内时 → **停止测试并询问用户**：

> 目标组件未发现可跨越权限边界的攻击面。继续测试大概率只能产出**同权限域（不可越权）的中低危缺陷**（如不可信输入导致的用户级代码执行、持久化注入、同域接口破坏数据）。是否进入扩展模式？

| 选项 | 行为 |
|------|------|
| ① 进入扩展模式 | 按下方「跨信任边界」标准评估，产出中低危报告 |
| ② 停止（严格模式，**默认**） | 仅输出"未发现越权漏洞"结论 |
| ③ 仅记录 | 记为观察项清单，不出正式漏洞报告 |

询问一次，答复作为**本次会话开关**，并在结论/报告头部注明本次采用的判定标准。

**扩展模式判定标准**：门槛从"跨权限边界"放宽为"**跨信任边界**"：

- ✅ 计入：不可信输入（外部文件/文件名/URL/网络数据/同域其他进程的总线调用）→ 在受害者上下文执行代码、破坏或泄露数据（**攻击者 ≠ 受害者**）
- ✅ 计入：同 UID 域内任意进程可调用且造成破坏的接口（攻击者可为同机受限进程）
- ❌ 仍不计入：用户对自身配置/数据的自操作；无任何信任边界跨越的操作

拒绝标准第 2 条随之**参数化**：严格模式 =「同权限域操作即拒绝」；扩展模式 =「仅『用户对自身资产的自操作』拒绝」。

**定级与报告**：CVSS 3.1 照常逐项评分，预期等级 低危~中危（0.1–6.9），并**必须标注"不可越权"**、在漏洞信息表填写 `权限影响` 字段（详见 report-template.md）。

### 优先级策略

**自研组件 > 开源组件**。kydima、ksaf、ukui、kysec、三权分立相关组件优先深挖。开源未修改的默认跳过。

### 测试路径优先级：探测优先，逆向兜底

**黑盒审计的主路径是探测，且"探测" = 枚举 + 参数注入首扫**。强制次序：

1. **① 枚举**：接口/方法/参数全部列出；
2. **② 参数注入首扫（先于一切静态分析）**：对每个可取字符串的参数（`s`/`as`/`a{sv}`/结构体成员）逐个打一轮注入载荷（见 dbus-authz.md「参数注入首扫」），以 marker + owner uid 取证——**通常几分钟即定论，是判定"是否经 shell / 是否转义"的第一手段**；
3. **③ 系统级验证**；
4. **④ 静态逆向**：仅当 ② 无果、或需解释原因/定位触发条件（配置门控、字段来源）时才用；纯本地无任何可调用接口的二进制才以静态为主。

**逆向能力边界（硬约束）**：无 IDA/Ghidra/反编译器时，逆向（objdump/nm/strings）**只用于"定位"**（哪个方法、哪个参数流入哪个 sink），**不用于"判定"**（是否经 shell、是否转义、是否安全）——**判定一律以黑盒 fuzz 结果为准**。

**两条硬禁令**：
- **枚举后未完成一轮参数 fuzz 前，禁止进入反汇编**；
- **逆向不跨函数追机制**（不得从一个汇点的调用方式外推另一个汇点）；黑盒一旦给出答案即停。

**反模式**：不得以未验证的假设（如"疑似走了安全路径"）终止探测。判定"不可达/非漏洞"之前，必须有一次系统级证据（`strace` 观测、文件/状态变化、报错分层）。**尤其禁止以"`grep call <sink>` 只找到一处"判定不可达**——信号/槽、回调、vtable 取的是函数地址，须按下方「可达性回溯」枚举全部六类引用形式。**同样禁止把"载荷未执行"当"不会执行"**——载荷若因前置失败提前返回，结论是"无效（inconclusive）"而非"无注入"（证据标准见 dbus-authz.md）。

**逆向止损线**：一旦探测已能支撑漏洞结论，即停止静态逆向；安全机制（白名单/Polkit/KYSEC 等）的**内部算法不深挖**——现象（如 journal 报 `corrupted`/`not loaded`）足以定位根因即可，余者转入报告「进一步分析建议」。判定"机制被绕过"前，先按「安全机制生效性核验」确认其已加载生效。

### 可达性回溯：疑似 sink → 攻击者入口

逆向发现疑似危险汇点（`system`/`popen`/`exec*`/写文件/`unlink`…）后，**必须回溯它如何被进入**。
只 grep 直接调用会漏判——信号/槽、回调、`std::function`、vtable 取的是**函数地址**，不是 `call`。

**反模式（禁止）**：`grep 'call.*<sink>'` 只找到一处 → 据此判定"不可达 / 仅 GUI 可达"。

**六类引用形式，逐一查（缺一即可能漏判）**：

| # | 形式 | 命令 |
|---|------|------|
| a | 直接调用 | `grep -nE 'call.*<sym>' dis.txt` |
| b | **取地址（最关键）** | `grep -nE '(lea\|mov\|push).*<sym>' dis.txt`；`readelf -rW <bin> \| grep <sym>`（`.data.rel.ro` 槽 = 指针表 / vtable / std::function） |
| c | **Qt 信号/槽** | connect 站点 = 同一小段内同时出现"信号""槽"两个地址实参；`strings -a <bin> \| grep -E '^(1\|2)<name>\('`（moc 元对象 1signal/2slot）；旧式 `SIGNAL()/SLOT()`、`QMetaObject::invokeMethod` 同法 |
| d | **D-Bus / Qt 自动导出** | `busctl --user tree/introspect`；`nm -C <bin> \| grep -E 'Adaptor\|registerObject\|closeEvent\|event\(\|timerEvent'`；`org.qtproject.Qt.QWidget.close()` → `QWidget::close` → `QCloseEvent` → `closeEvent()` |
| e | 定时器/事件循环/队列 | `nm -C <bin> \| grep -E 'QTimer\|singleShot\|startTimer\|invokeMethod'`；`QueuedConnection` / `postEvent` |
| f | 配置门控分支 | 见下方"门控溯源" |

**回溯流程**：sink 符号 → 全形式引用 → 每条引用地址**回映射宿主函数**（`awk '/^[0-9a-f]+ <[^>]*>:/{fn=$0} /<ref_addr>/{print fn}' dis.txt`）→ 对宿主**递归**再问"谁进入它" → 终止于攻击者入口（D-Bus 方法 / Adaptor slot / 导出 event / main+argv / socket / 信号 emit），入口须**黑盒证实**。

**门控溯源（键字符串 → 全局偏移 → 判定分支）**：

```bash
strings -t x <bin> | grep '<General/key>'                    # 键字符串 vaddr
objdump -drwC -M intel <bin> | grep -nE 'lea.*# <vaddr>'      # 谁引用它（QSettings::value + toBool）
# 赋值形态: lea key; call QSettings::value; call QVariant::toBool; mov %al,0x1a(%rbp) ← 0x1a 即偏移
objdump -drwC -M intel <bin> | grep -nE '(cmp|test|movzbl).*0x1a\('   # 判定分支
```

**判定"不可达"的证据要求**：① 六类引用形式逐一给出否定证据；② 至少一条黑盒证据（`strace` / 标记文件 / 状态变化）。

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

### 审计边界（必须先做）

**目标组件的唯一标识**：源码包名 / 应用 ID / 用户给定的路径。**审计范围 = 该标识直接归属的文件、进程、服务、策略。**

- 与本组件**相关但归属其他组件**的实体（宿主框架、运行时、基础层、第三方守护进程）→ **不测试**，仅记录为"关联观察"附注（不赋漏洞编号、不进 POC、不参与结论）。
- **归属校验**（测试任何运行时实体前必须执行）：
  - 进程/二进制：`readlink /proc/PID/exe` → `dpkg -S` / `rpm -qf` 查询归属
  - D-Bus/PolicyKit：策略文件是否以组件唯一标识命名（`find /etc/dbus-1 /usr/share/dbus-1 /usr/share/polkit-1 -name "*<标识>*"`）
  - 挂载/沙箱：是否由组件自身的配置（文件清单内的配置、包声明文件）产生
  - 校验结果属于本组件 → 可测；不属于 → 归"关联观察"，不测试

### 前置步骤：执行组件

**不运行就测试等于白测。** 有 `.service` → `systemctl start`。有 `.ko` → `insmod`/`modprobe`。已在运行的检查状态即可。无法启动的记录原因，跳过运行时测试只测静态项。

### 门禁检查

每个攻击面先确认适用性，不适用则跳过：

| 攻击面 | 有意义的条件 | 不满足则 |
|--------|------------|---------|
| SUID/Cap | `find`/`getcap` 有输出 | 跳过 |
| D-Bus | 有 D-Bus 策略文件、或用户指定了服务、**或组件有自己的私有 socket（抽象 / 文件系统）** | 跳过 |
| PolicyKit | 有 policy 文件或用户指定了 action | 跳过 |
| 系统状态 diff | 有 `.service`/`.ko` 且可启动，**或为图形会话应用（可运行）** | 跳过 |
| 会话总线 | 组件可运行（GUI/桌面应用常见） | 跳过 |
| 非特权目标 | 权限摸底显示全部攻击面均在登录用户权限域内 | 触发扩展模式门控（见「可选扩展模式」） |
| sudo/cron/Unix socket | 对应命令有输出（**抽象套接字用 `ss -xlnp` 查，`find -type s` 看不到**）| 跳过 |

### 模式 A：组件驱动

详见 [references/component-discovery.md](references/component-discovery.md)。**先读其中的 A0-A2 锁定审计边界，再继续。**

| 步骤 | 内容 |
|------|------|
| A0 | 锁定组件边界 + 取文件清单（多形态探测见 component-discovery.md A0）|
| A1 | 组件分类（内核模块/守护进程/工具/配置/库）|
| A2 | 权限摸底（SUID/Cap/D-Bus/PolicyKit/配置）|
| A3 | 启服前后 diff（netlink/securityfs/系统总线 + 会话总线/socket）|
| A4 | 二进制分析（checksec/nm/strings/格式化字符串）（探测无果时使用）|
| A5 | strace 按 syscall 分类跟踪 |
| A6 | 进入统一验证 |

### 模式 B：二进制驱动

详见 [references/suid-analysis.md](references/suid-analysis.md)。

> **仅当目标无任何可调用接口（纯本地二进制），或接口探测无果时，才以静态分析（B2-B4）为主**。若目标存在可调用接口，先按模式 C/E 探测；静态仅在需要解释探测结果时使用。

| 步骤 | 内容 |
|------|------|
| B0 | 权限基线 |
| B1 | 基本属性（file/ls -la/rpm -qf）|
| B2 | 安全特性（checksec/readelf：CANARY/NX/PIE/RELRO）（探测无果时使用）|
| B3 | 导入函数（nm -D：system/popen/exec/sprintf/strcpy）（探测无果时使用）|
| B4 | 字符串分析（关键词 + 格式化字符串 + 文件路径）（探测无果时使用）|
| B5 | strace 按 syscall 分类跟踪 |
| B6 | 进入统一验证 |

### 模式 C：D-Bus 驱动

详见 [references/dbus-authz.md](references/dbus-authz.md)。

| 步骤 | 内容 |
|------|------|
| C0 | 权限基线 + **拓扑判定**（XML Policy + PolicyKit action + 会话总线默认策略；先判 system / session / **P2P**）|
| C1 | `busctl tree` + `busctl introspect` + `busctl status`（服务级 + 会话级）；**`busctl` 找不到时用 `ss -xlnp` 找 P2P / 抽象套接字**（不在总线上者对 busctl 完全不可见）|
| C1.5 | **跨用户连接实测**（P2P 专项，黑盒优先；见 dbus-authz.md「第三种拓扑」）+ 对端 uid 校验符号检查（`g_credentials_get_unix_user` / `sd_bus_creds_get_euid` 等，**仅用于解释结果**）|
| C2 | 关键词定级（P0-P3，详见 dbus-authz.md）|
| C2.5 | **参数注入首扫（先于静态逆向）**：对每个 `s/as/a{sv}` 参数打一轮注入载荷，marker + owner uid 取证（详见 dbus-authz.md「参数注入首扫」）|
| C2.6 | 入口↔汇点可达性回溯（**仅当首扫无果或需解释时**；sink → 入口，见「可达性回溯：疑似 sink → 攻击者入口」）|
| C3 | 普通用户调用（系统总线 `--system` / 会话总线 `--user`；**P2P 用 `new_for_address_sync`，跨用户加 `sudo -u nobody`**）|
| C4 | 系统级命令验证 |
| C5 | 确认漏洞后，Python 深入利用（详见 deep-exploitation.md）|

> **枚举必须完整**：`busctl tree <服务>` 列出全部对象路径，逐路径 `introspect`。**根路径只返回 Introspectable/Peer ≠ 无攻击面**——接口常挂在子对象路径下。GUI/桌面组件优先用 `busctl --user` 枚举会话总线（Qt 应用还会自动导出 `org.qtproject.Qt.QWidget` 等接口，见 dbus-authz.md）。注意 `QWidget.close()` 会落到 `closeEvent` 等事件入口，而 `closeEvent` 可能再 emit 信号触发清理/删除槽——必要时把方法入口一路追到 sink（**首扫之后的解释性步骤**，见「可达性回溯」）。**另注意 D-Bus 有三种拓扑**：system / session / **点对点（P2P，无 daemon）**。P2P 服务 `busctl` 完全看不到，且 daemon 侧管控（XML Policy / limitCtl / polkit）一律缺席——那里跨用户**可测**，见 dbus-authz.md「第三种拓扑」。

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

#### 安全机制生效性核验（判"绕过"之前必做）

判定"白名单/调用者校验/Polkit/KYSEC 被绕过"**之前**，必须先证明该机制**已加载生效**；否则"看似未拦截"可能只是"机制根本没加载"，根因与修法截然不同：

| 机制 | 生效性证据 |
|------|-----------|
| D-Bus 调用者白名单（`.limit`）| journal 中 limitCtl 的 `Insert new file … successful` / `verify check successful`（反之 `corrupted, whitelist invalid` = 未加载） |
| Polkit | `pkaction --action-id <id> --verbose` 输出 implicit 值；进程是否实际调用 `CheckAuthorization`（无该调用 = 未集成） |
| KYSEC/ksaf | `cat /sys/kernel/security/ksaf/status`（强制模式位） |

- 机制**未加载** → 配置缺陷（修：修配置/重新签名/开启强制），**不是**"绕过"。
- 机制**已加载但仍可越权** → 才是绕过漏洞。

POC 格式 —— SUID/能力（5 步；**基线一律非交互**——勿用会弹密码的命令，改用 `pkcheck --action-id <action> --process $$` / `login1 CanReboot` / 自建文件属主对照）：

```bash
## [P0/P1] <路径> — <说明>

# 步骤0：权限基线（非交互，勿触发密码弹窗）
id
<普通用户执行该操作的非交互等价形式> 2>&1   # 应被拒绝（权限不够 / Operation not permitted）
# 需证"本应拦截"时用：pkcheck --action-id <action> --process $$   # rc=2 = 本应认证

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

# 步骤2：普通用户调用（系统总线 `--system`；会话总线服务改用 `busctl --user call`）
busctl --system call <服务> <路径> <接口> <方法> <参数>
#   P2P/直连服务不挂总线 → busctl 不可用，改用：
#   Gio.DBusConnection.new_for_address_sync('unix:abstract=<名>', ...) + conn.call_sync(...)
#   跨用户测试：把整段连接+调用脚本用 `sudo -u nobody python3` 再跑一次

# 步骤3：系统级验证 + 恢复
<系统级验证命令>
<恢复命令>
```

D-Bus 深入利用（确认漏洞后）详见 [references/deep-exploitation.md](references/deep-exploitation.md)：白名单管控绕过（**遇到管控才绕，不上来就绕；LD_PRELOAD 优先**，bwrap/PYTHONPATH 限宽松服务，ptrace 替补）、任意文件写（SSH key/cron/systemd/sudoers.d/PAM）、路径穿越、提权链。

### 产物结构

- 每漏洞一个目录：`<目标名>/vuln-00N/`，内含 `report.md` + `poc.py`（**Python 优先**；仅单条命令即可证明时才用 `poc.sh`）。骨架见 [references/poc-template.py](references/poc-template.py)。
- 编号规则：`vuln-001`、`vuln-002`… 每组件从 001 递增，目录名与报告编号一致。
- test-log 固定：`<目标名>/test-log.md`。

### PoC 规范

- **Python 优先**（`poc.py`），骨架见 [references/poc-template.py](references/poc-template.py)。
- **彩色输出**：ANSI 常量 + `step()/ok()/bad()/info()` 助手；非 tty 自动降级无颜色。**阶段可合并、不强凑六段**（如 Presence+Introspection 合并、Reachability/Boundary 内联为 Impact 中一行 uid 与对照）——报告「验证情况」仍须覆盖六阶段的内容。
- **基线必须非交互**：禁止在基线/对照阶段运行会触发认证或弹密码的命令（如 `systemctl reboot`）；改用非交互对照——`pkcheck --action-id <action> --process $$`（rc=2 = 本应拦截）、`busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot`（`s "challenge"` = 需认证）、`id`、或"自建文件属主对照"（自建文件 owner=自身 uid）。
- **基线必须与 Impact 同族操作**（重启对重启、root 写文件对 root 写文件）——否则对照不成立；无法同族时不设基线并说明。
- **Impact 覆盖尽可能多的可达危险方法**（批量演示多个注入点/多个特权方法）；破坏性方法标注"**可达但不执行（系统稳定性）**"及其对应 root 命令。
- **末行必须是三态结论之一**（stdout 最后一行，便于批量采集）：`漏洞存在` / `漏洞不存在` / `poc 执行失败，请调整环境或改用其他方式验证`（退出码 0 / 1 / 2）。
- **交付前必须实机执行并留证**：未跑通过的 PoC 不得写入报告。已知失败原因是目标进程未运行 → PoC 必须 `ensure_process()` **幂等自拉起**（探测 GUI 会话环境变量 + 等待总线服务注册后再继续）。
- **自清理**：`finally` 还原配置/数据库（先备份）、删除标记文件、恢复原状态；报告「验证情况 · Cleanup」须给出清理后回显。
- **验证不依赖接口返回值**：用系统级证据（标记文件 + `owner uid`、`strace -f -e trace=execve`）。

### 报告

按 [references/report-template.md](references/report-template.md) 的章节结构输出。漏洞描述首句用陈述句 `<组件> 存在 <漏洞类型> 漏洞`（**不加粗**；**不举例、不写具体组件名与漏洞类型**）；CVSS 3.1 写"向量 + 一行依据"；须含六阶段「验证情况」；**正文 ≤ 70 行**。

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

按 report-template.md 完整输出（vuln 编号 + 漏洞信息表 + 内部/外部概述 + 漏洞原因 + POC + 修复建议）。

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
| [references/cap-analysis.md](references/cap-analysis.md) | 能力组合风险矩阵、进程内代码执行注入（LD_PRELOAD / Qt 插件目录劫持） |
| [references/dbus-authz.md](references/dbus-authz.md) | D-Bus 方法关键词映射（P0-P3）、决策树、参数注入探测、白名单管控识别、验证命令、**第三种拓扑（P2P / 抽象套接字）跨用户越权** |
| [references/polkit-authz.md](references/polkit-authz.md) | PolicyKit allow_active 审计、pkexec 用法 |
| [references/deep-exploitation.md](references/deep-exploitation.md) | D-Bus 深入利用：白名单管控绕过四法（LD_PRELOAD 首选/bwrap/PYTHONPATH/ptrace）、任意文件写利用链、提权链 Python 模板、符号链接绕过 |
| [references/report-template.md](references/report-template.md) | 漏洞报告模板、CVSS 3.1 严格评分指南、危害判定对照表 |
| [references/poc-template.py](references/poc-template.py) | Python PoC 骨架：彩色输出、三态结论、幂等自拉起、自清理 |
| [references/cvss31_calc.py](references/cvss31_calc.py) | CVSS 3.1 base-score 计算器（无依赖）；报告定稿前必跑并粘贴分数 |

---

## 输出前自检

**所有模式**：
- [ ] 步骤 0 权限基线已完成
- [ ] 系统级命令验证，未依赖返回值
- [ ] CVSS 评分逐项有依据
- [ ] 审计边界已锁定，清单外实体仅记为关联观察、未测试
- [ ] 测试范围未超出用户指定
- [ ] 门禁检查已执行，不适用项已标注原因
- [ ] 组件已执行后才做的运行时检查（D-Bus/端口/netlink）
- [ ] **探测优先顺序已遵守**（枚举 → 参数注入首扫 → 系统级验证 → 静态仅兜底；**首扫未完成前未进入反汇编**）
- [ ] **字符串参数注入首扫已完成**（枚举后、任何静态逆向之前，逐参数打过载荷并记录 marker/owner uid）
- [ ] **每个"无注入"结论满足证据标准**（载荷确已到达执行点：构造命令见于日志 / strace 见 execve / 补齐前置后仍无 marker；前置失败 = 结论无效，不得记为"无注入"）
- [ ] **会话总线已 diff**（组件启动前后 `busctl --user list` 对比）
- [ ] **接口全量枚举**（`busctl tree` 的全部对象路径均已 `introspect`，无"根路径空即放弃"）
- [ ] **D-Bus 拓扑已判定**（system / session / P2P）；`busctl` 找不到时已用 `ss -xlnp` 补查抽象 / P2P 套接字
- [ ] **P2P 跨用户已实测**（换 uid 连接）；`ECONNREFUSED` 已排除为"无监听者"，未记为安全结论
- [ ] **"方法可调用"与"影响已证实"已分开取证**（返回空 / 操作失败不计为影响已证实）
- [ ] **无未验证假设终止探测**（"不可达/非漏洞"结论有系统级证据）
- [ ] test-log.md 已记录关键步骤
- [ ] **疑似 sink 已做可达性回溯**（六类引用形式逐一查，尤其取地址/信号槽/D-Bus 导出）；"不可达"结论附否定证据 + 一条黑盒证据
- [ ] 配置门控已溯源到「键 ↔ 全局偏移 ↔ 判定分支」
- [ ] **PoC 已实机运行并留存输出**（幂等自拉起、自清理已还原）；未跑通过不得写入报告
- [ ] 报告漏洞描述**首句**为 `<组件> 存在 <漏洞类型> 漏洞`
- [ ] 报告含六阶段验证情况（Presence→Introspection→Reachability→Boundary→Impact→Cleanup）
- [ ] 每漏洞产出 `<目标名>/vuln-00N/report.md + poc.py`，编号连续
- [ ] 文件写入 `<目标名>/`，未在用户工作目录留临时文件
- [ ] **CVSS 分数由 `references/cvss31_calc.py` 复核并粘贴**（不手算）
- [ ] **安全机制生效性已核验**（判"绕过"前已证明机制加载：limitCtl/polkit/ksaf）
- [ ] **信息暴露已评估**（world-readable 敏感文件按三分类处理，无静默丢弃；非漏洞项亦写一行结论）
- [ ] **静态声明 vs 运行时可达已记录**（D-Bus 方法逐个实测，声明存在但 UnknownMethod 的方法已标注）

**模式 A**：
- [ ] 组件边界已锁定（文件清单完整且归属校验通过），组件分类正确
- [ ] 系统状态 diff 已执行（含会话总线维度）
- [ ] 非特权目标已触发扩展模式门控，开关状态已与用户确认

**模式 B**：
- [ ] 已确认目标无可用接口（或探测无果）后才以静态为主，并记录原因
- [ ] checksec / nm -D / strings（含格式化字符串）/ strace 四步已完成

**模式 C/D**：
- [ ] P0/P1 方法已标记并测试，陌生术语已查背景
- [ ] 全对象路径 × 接口 × 方法签名已枚举（含会话总线与 Qt 自动导出接口）
- [ ] **P2P / 抽象套接字已纳入**：`busctl` 未命中时用 `ss -xlnp` 补查；已检查对端 uid 校验符号（`g_credentials_get_unix_user` / `sd_bus_creds_get_euid`）并做跨用户连接实测
- [ ] 参数深挖 fuzz 已评估（数组/结构体逐元素、二阶/存储型、组合载荷；基础注入首扫见"所有模式"）
- [ ] 二阶/配置门控触发路径已评估（持久化载荷 + 重载 + 门控开关）
- [ ] D-Bus 白名单管控：先确认受控（.limit/yaml + 报错分层）才评估绕过，LD_PRELOAD 优先，RootOnly 类直接放弃

**模式 E**：
- [ ] 权限和注入点已检查

**结论**：
- [ ] 有漏洞 → 完整 POC + CVSS 依据 + 修复建议
- [ ] 无漏洞 → 写清原因，不强挖，不自行扩大范围
- [ ] 目标不存在 → 已报告，未自行扩展扫描
