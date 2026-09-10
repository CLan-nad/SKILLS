---
name: ghidra-mcp-vuln-hunter
description: 基于 Ghidra MCP 工具链对加载的二进制进行漏洞挖掘。从攻击面获取开始，识别业务接口，深入分析调用链，确认漏洞并形成 POC。适用于各类用户态程序（D-Bus 服务、netlink、socket、配置解析、守护进程等）的逆向漏洞分析。make sure to use this skill whenever the user wants to reverse a binary to hunt vulnerabilities, analyze call chains for security issues, locate business logic entry points in a binary, or confirm and build POC for suspected vulnerabilities using Ghidra MCP tools.
author: security-researcher
version: 0.2
triggers:
  - 二进制漏洞挖掘
  - ghidra mcp 逆向分析
  - 调用链安全分析
  - 反编译确认漏洞
output:
  default: 漏洞分析报告 <target>/report.md + <target>/poc.py|poc.sh
---

# ghidra-mcp-vuln-hunter

基于 Ghidra MCP 工具链的二进制漏洞挖掘。本 skill 定义分析主流程，每个环节的详细操作在 `references/` 下对应文件中，按需读取。

## 分析主流程

```
⓪ 环境确认 → ① 程序概览 → ② 攻击面获取 → ③ 识别业务接口 → ④ 深入分析调用链 → ⑤ 漏洞确认 → ⑥ POC 形成
```

### ⓪ 环境确认（先于一切逆向工作）

**先确认本机/目标是否真实存在被服务的运行环境**（问用户或直接探测目标进程、systemd 单元、系统总线注册）。这个事实改变后面所有环节的姿态：

| 环境状态 | 攻击面（②③） | POC（⑥） |
|---|---|---|
| **真实环境存在** | **首选 `busctl introspect` 等黑盒探测**核对总线名/接口/方法签名（一次拿到准确事实），静态梳理只补黑盒看不到的部分 | **必须端到端实际执行并拿观察物实证**，静态推演不得作为最终证据 |
| 仅二进制（无环境） | 纯静态梳理（模式 B） | 交 POC 脚本 + 判定方法，标注"待在真实环境验证" |

黑盒环境存在却跳过环境确认，会造成：攻击面里的名称/签名凭静态猜测（易错位，如总线名 `org.kaiming.proxy` vs 接口 `org.kaiming.proxy.system`）、POC 无法闭环（标注已停步于静态推断）。

### ① 程序概览

先了解加载的二进制，建立分析上下文：

| 操作 | MCP 工具 |
|------|---------|
| 加载程序（无头模式） | `load_program(file=...)` |
| 触发自动分析（无头必做） | `reanalyze(program=...)` |
| 获取程序概览 | `get_current_program_info` |
| 确认当前程序（多程序时） | `list_open_programs` |

了解：架构、位数、基址、函数数量、导入符号（用了哪些库）。**基址用于地址换算**，导入符号决定后续用哪类框架知识。

### ② 攻击面获取

确定目标暴露了哪些接口/入口。攻击面来源可插拔，优先使用黑盒结果：

- **模式 A（推荐）**：读取黑盒阶段已产出的攻击面清单 `{接口, 方法, 对象路径, 签名}`
- **模式 B**：黑盒未提供时，在二进制内独立梳理（D-Bus 接口、netlink family、socket 路径、文件路径等）

> 详细操作见 [references/attack-surface.md](references/attack-surface.md)

### ③ 识别业务接口

把攻击面清单**映射到二进制内的处理函数**。这是数据流分析的第一步——攻击面是"目标有什么接口"，这里要找到"接口在代码里由哪个函数处理"。

识别方法因入口类型而异：框架感知（GDBus/QtDBus 样板代码识别）、netlink 协议号、socket 消息循环、程序参数解析、配置解析函数等。

> 详细操作见 [references/entry-point-recognition.md](references/entry-point-recognition.md)

产出：入口清单 `{接口, 处理函数地址, 参数签名}`。

### ④ 深入分析调用链

对每个入口，沿数据流追踪到敏感操作，获取完整调用链，并识别、评估其中的阻断条件（校验点）。

- 主线：**从入口参数（污点源）向下追踪**，在每个处理步骤验证数据去向与校验情况
- 可选：命令执行类危险函数（exec/system/popen）数量少时，反向枚举调用点向上回溯

> 详细操作见 [references/call-chain-analysis.md](references/call-chain-analysis.md)

### ⑤ 漏洞确认

对疑点位置，对照漏洞模式验证三件事：

1. **可达性**：攻击者能否到达这里（暴露面、权限要求）
2. **可控性**：攻击者能否控制关键数据（输入来源、是否被校验）
3. **校验缺失**：是否在错误的信任边界后使用了数据（过滤/白名单/权限检查缺失或可绕过）

> 详细操作见 [references/vuln-patterns.md](references/vuln-patterns.md)

### ⑥ POC 形成

- **最小化验证**：构造触发条件的最小输入，证明漏洞存在，不做过度利用
- 实现形式：优先 Python 脚本（dbus-python / socket / ctypes），或 bash/sh（busctl call / dbus-send / nc）
- 输出：`<target>/poc.py` 或 `<target>/poc.sh`，附执行结果
- 记录触发条件与前置约束（如需要的权限、有效 PID 等）

#### POC 实际执行（强制，目标环境真实存在时）

**目标服务所在真实环境可直接触达时，POC 必须实际运行验证，不允许只交付静态推演。** 步骤：

1. **核对接口事实**：在真实环境用 `busctl introspect <bus> <path>` / `ss` / `netstat` 等拿到**确切的总线名/接口名/方法签名**——静态分析里的名字可能错位（如总线名是 `org.kaiming.proxy` 而接口才是 `org.kaiming.proxy.system`；签名是 `(iss)` 而非 `(is)`）。签名/名称错误是 POC 失败的首要原因
2. **实际执行 POC**，用可无副作用的观察物做判定标记（`touch` 空文件、`id > file`），读取结果确认（属主、内容、进程输出）
3. **需要时用 strace 锚定**：静态推断的执行语义可能与实际不符（例：静态看是"shell 拼接注入"，实际 `exec=` 前缀的含义是"赋值后直接执行可执行文件"，最优 POC 是 `exec=<bin> <args>; <cmd2>` 而非依赖 `;` 顺序）；配合动态结果修正 payload
4. **记录实证结果**：POC 执行输出 + 观察物截图/内容 + 身份（uid），写进报告的 POC 小节；仅静态推断的证据降级为"待动态确认"

判定标准：POC 至少完成一次**端到端成功执行**（观察物出现），报告才允许标注"已确认"；执行不成功则回到"动态验证与排查"，不得跳过。

#### 动态验证与排查（POC 执行不成功时）

POC 失败时用动态手段排查，静态分析与动态验证结合：

- **strace 跟踪系统调用**：`strace -f -e trace=execve,open,openat,read,write ./target ...`，确认程序实际执行了什么，适用于：
  - POC 期望命令注入但无效果 → 看是否真的走到 `execve`
  - 路径穿越/文件操作不生效 → 看 `open`/`openat` 实际访问的路径
  - 校验条件卡住（如 namespace 校验）→ 看 `open("/proc/<pid>/ns/mnt")` 是否发生
- **ltrace 跟踪库调用**（可选）：确认 `popen`/`system`/`strcmp` 等库函数是否被调用及参数
- **调试器**（可选）：断点设在目标函数，观察参数值是否符合预期
- 对比动态观察与静态分析结论，修正对调用链的理解（如实际走了另一分支、校验点在别处）

strace 是逆向动态验证的基本方法：静态分析给出"应该发生什么"，动态观察确认"实际发生什么"，两者对不上时往往就是漏掉了某个分支或校验。

## 证据标准

### 漏洞（finding）必须满足

1. 有明确的输入来源（用户态/低权限可控）
2. 有清楚的到达路径
3. 有缺失、错误或不一致的校验
4. 有危险操作（越界访问、命令执行、路径穿越、权限绕过等）
5. 有合理的安全影响

### 审计线索（证据不足时）

只能证明"代码不稳健"但无法证明可控性或安全影响时，归类为审计线索，写清：已确认事实、尚未确认、下一步应查看。

### finding 输出格式

- 组件 / 函数地址 / 入口点
- 攻击者能力 / 可控数据
- 漏洞类型 / 触发路径
- 关键代码行为 / 缺失校验
- 安全影响 / 利用约束
- 修复建议 / 置信度 / 待确认问题

## 操作-工具映射速查

| 分析操作 | MCP 工具 |
|---------|---------|
| 加载程序 / 触发分析 | `load_program`、`reanalyze`、`get_current_program_info` |
| 搜索字符串 / 定位 | `search_strings`、`list_strings`、`list_functions`、`get_function_by_address` |
| 交叉引用追踪 | `get_xrefs_to`、`get_xrefs_from`、`get_bulk_xrefs` |
| 数据流分析 | `analyze_dataflow`（PCode 值传播，forward/backward） |
| 反编译 / 反汇编 | `decompile_function`、`disassemble_function`、`get_function_signature` |
| 危险函数枚举 | `list_imports`（全量拉取后本地过滤标准库符号） |
| 调用关系 | `get_function_callers`、`get_function_callees` |
| 复合分析 | `analyze_function_complete`、`find_similar_functions` |
| 信息辅助 | `get_bytes`、`list_globals`、`get_global_value`、`get_entry_points` |

## 目录

```
SKILL.md                        ← 本文件：主流程 + 证据标准 + POC
references/
├── attack-surface.md           ← ② 攻击面获取（黑盒读取 / 独立梳理）
├── entry-point-recognition.md  ← ③ 识别业务接口（框架感知 + 各类入口）
├── call-chain-analysis.md      ← ④ 调用链分析（污点追踪 + 逆向技巧 + 阻断条件）
└── vuln-patterns.md            ← ⑤ 漏洞模式与三问题检查
```
