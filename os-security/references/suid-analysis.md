# SUID / Capabilities 未授权漏洞挖掘方法

## 核心判定标准

**普通用户能否通过该 SUID/cap 执行原本需要 root 的操作 → 能 = 未授权漏洞**

五步判定（拒绝标准、优先级策略见 SKILL.md「核心判断原则」）：

```
0. 权限边界：普通用户默认能做什么？  → 基线建立（必须先做）
1. 功能识别：这个 SUID/cap 能做什么？ → 功能分析
2. 可达性：普通用户能调用吗？        → 调用测试
3. 影响验证：操作真的生效了吗？      → 系统级验证
4. 权限对比：是否绕过了应有权限？    → 对比基线
```

**四步全部为 YES（且步骤 0 确认操作需要 root） → 确认未授权漏洞**

---

## 阶段零：权限边界基线（必须首先完成）

```bash
id && whoami                          # 确认为普通用户，非 root
<目标操作> 2>&1                       # 直接执行，观察是否需要认证（polkit 弹窗/报错）
pkaction --action-id <action> --verbose | grep implicit   # 对齐同服务其他 action
```

基线结论：`[默认需要 root]` → 继续；`[默认允许普通用户]` → 停止，判定为非漏洞。
（`modify.own` 允许 / `modify.system` 需 auth_admin = 正常设计，不是漏洞。）

---

## 阶段一：侦察

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

## 麒麟特有组件速查

| 组件 | 二进制 | 功能 | 验证重点 |
|------|-------|------|---------|
| KYSEC | kydima_set | 安全监控开关 | 能否关闭监控 |
| UKUI | ukui-screensaver-checkpass | 锁屏验证 | 能否绕过锁屏 |
| UKUI | changeuserpwd | 密码修改 | 能否修改他人密码 |
| 三权分立 | security-reinforce-daemon | 安全加固 | 能否注入进程 |
| 三权分立 | ksaf_auth | 认证 | 能否绕过认证 |
| 可信计算 | kytrust_config | 信任链配置 | 能否篡改启动链 |
| 盒子 | boxmount/boxumount | 挂载管理 | 能否挂载/卸载任意路径 |

---

## 相邻攻击面指引

- PolicyKit 策略审计 → 模式 D：[polkit-authz.md](polkit-authz.md)
- 能力组合风险矩阵、进程内代码执行注入（LD_PRELOAD / Qt 插件目录劫持）、已知能力目标速查 → [cap-analysis.md](cap-analysis.md)