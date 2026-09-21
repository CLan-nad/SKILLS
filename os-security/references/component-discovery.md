# 组件发现与攻击面枚举

> 当用户给出组件名（如 `kylin-disk-encryption`）时使用本方法，从零开始摸底组件的完整攻击面。

### 通信机制速查

Linux 组件通过以下机制暴露攻击面，按组件类型匹配：

| 通信机制 | 产生来源 | 发现命令 | 测试方向 |
|---------|---------|---------|---------|
| D-Bus | 守护进程 (.service) | `busctl --system list`（系统总线）/ `busctl --user list`（会话总线）| 方法枚举 → 策略审计 → 未授权调用；**逐对象路径枚举**（根路径空 ≠ 安全）|
| Netlink | 内核模块 (.ko) | `cat /proc/net/netlink` | 协议号 → Python socket 交互 |
| 系统调用 | SUID/Cap 二进制 | `strings`/`strace` | 危险函数 → 参数注入 → 权限绕过 |
| Unix Socket | 守护进程 | `ss -xlpn` | 权限检查 → 连接测试 |
| loopback TCP/UDP | 守护进程 | `ss -tlnp \| grep 127` | 端口连接 → 认证测试 |
| securityfs | 内核模块 | `ls /sys/kernel/security/` | 读写权限测试 |
| 配置文件 | 所有类型 | 文件清单过滤 | 权限检查 → 注入点分析 |

---

## A0：锁定组件边界与信息收集

先**确定组件由何种机制管理**，锁定审计边界，再取文件清单。

### A0-a：形态探测

```bash
# RPM 系
rpm -qa 2>/dev/null | grep -i <关键字>

# Debian 系
dpkg -l 2>/dev/null | grep -i <关键字>
apt show <组件名> 2>/dev/null   # 备选

# 应用分发框架（snap/flatpak 等）
snap list 2>/dev/null | grep -i <关键字>
flatpak list 2>/dev/null | grep -i <关键字>

# 入口定位
which <组件名>
```

### 分支判定

| 形态 | 判定特征 | 唯一标识 | 文件清单命令 | 边界 |
|------|---------|---------|-------------|------|
| RPM 系 | `rpm -qa` 有输出 | 源码包名 | `rpm -ql <包名>` | 包文件清单 |
| Debian 系 | `dpkg -l` 有输出 | 源码包名 | `dpkg -L <包名>` | 包文件清单 |
| 应用分发框架（少见） | 主流包管理器无归属 + 入口指向框架托管目录 | 应用 ID | **先确定管理该组件的命令/工具**（入口 `which`、安装目录观察、框架自带的管理/查询接口），再取其文件清单 | **应用 ID + 应用层文件**；运行时层/基础层/宿主服务归属框架组件，**不并入审计边界** |

> 应用分发框架形态不预设具体框架名称：先通过入口与目录确定"由什么工具管理"，再使用该工具公开的查询/管理界面取清单。主流包管理器可归属的组件一律走前两行。

### A0-b：输出

1. **文件清单**：组件自身安装的文件（按下方解读分组）。
2. **边界判定结论**：明确"组件自身 = X；关联但排除 = Y"（Y 为运行时/基础层/宿主服务等关联实体，记录为关联观察，不测试）。

### 文件清单解读

拿到文件清单后（RPM 系 `rpm -ql <包名>`，Debian 系 `dpkg -L <包名>`，应用分发框架用其管理工具接口），按文件类型分组：

```bash
# 文件清单写入变量（示例取 Debian 系，RPM 系用 rpm -ql）
FILE_LIST=$(dpkg -L <包名> 2>/dev/null || rpm -ql <包名> 2>/dev/null)

# 二进制文件
echo "$FILE_LIST" | grep -E '^/(usr/)?s?bin/'

# 库文件
echo "$FILE_LIST" | grep '\.so'

# 配置文件
echo "$FILE_LIST" | grep -E '\.(conf|cfg|xml|policy|rules)$'

# systemd 服务
echo "$FILE_LIST" | grep '\.service$'

# 内核模块
echo "$FILE_LIST" | grep '\.ko$'
```

---

## A1：组件分类

根据文件清单中的文件类型，判定组件属于哪一类。一个组件可能同时属于多类。

| 类型 | 文件特征 | 攻击面优先级 | 说明 |
|------|---------|-------------|------|
| 内核模块 | `.ko` 文件 | netlink、securityfs、module params、ioctl | 需 `insmod` 后测试 |
| 守护进程 | 二进制 + `.service` | D-Bus、监听端口、配置文件、SUID/Cap | 需 `systemctl start` 后测试 |
| 用户态工具 | 二进制（无 service） | SUID/Cap、命令行参数注入 | 可直接执行测试 |
| 配置文件 | `.conf`/`.policy`/`.xml` | 文件权限、内容注入点 | 几乎无独立攻击面，配合守护进程测试 |
| 库文件 | `.so` | 导出符号、LD_PRELOAD | 攻击面较小，配合调用方测试 |

**分类决策逻辑**：

```
有 .ko 文件？
  ├─ 是 → 内核模块，优先查 netlink/securityfs/ioctl
  └─ 否 → 有 .service 文件？
            ├─ 是 → 守护进程，启动后查 D-Bus/端口/配置
            └─ 否 → 有二进制？
                      ├─ 是 → 用户态工具，查 SUID/Cap/参数
                      └─ 否 → 纯配置/库，攻击面极小
```

---

## A1.5：归属校验（对运行时实体强制）  <!-- 放在 A2 前 -->

对组件运行过程中接触到的每个实体（进程、D-Bus 服务、PolicyKit action、挂载点），先确认归属，
再决定是否测试：

| 实体 | 校验方法 | 归属本组件的判定 |
|------|---------|-----------------|
| 进程/二进制 | `readlink /proc/PID/exe` → `dpkg -S` / `rpm -qf` 查询 | 路径落在组件文件清单内 |
| D-Bus 服务 | 服务进程 exe 归属 + 策略文件命名 | 策略文件以组件名命名（`find /etc/dbus-1 /usr/share/dbus-1 -name "*<组件名>*"`）|
| PolicyKit action | `pkaction` 输出 + action 文件路径 | action 文件以组件名命名 |
| 挂载/沙箱 | 挂载源路径与生成配置 | 由组件自身配置文件/包声明产生 |

**判定**：落入组件清单 → 可测；否则记入"关联观察"，不测试、不赋编号、不进 POC。

## A2：权限与接口摸底

对组件安装的所有文件执行权限和接口检查：

### SUID/SGID 检查

```bash
find <文件清单> -perm /6000 2>/dev/null
# SUID (4000) 或 SGID (2000) → 高价值目标
```

### Capabilities 检查

```bash
# 对每个二进制检查
getcap <二进制路径>
# 有 cap_* → 按 cap-analysis.md 中的组合风险矩阵评估
```

### D-Bus 配置检查

```bash
# 查找组件关联的 D-Bus 策略文件（系统总线 + 会话总线 + 激活文件）
find /etc/dbus-1 /usr/share/dbus-1 -name "*<组件名>*" 2>/dev/null

# 查看策略是否全局开放
cat <dbus-policy-file> | grep -A5 'context="default"'
# allow + 无限制 → 任何用户可调用
# deny → 需要特定用户

# 会话总线（GUI/桌面组件必查）——默认策略 = 同 UID 任意进程可调用
find /etc/dbus-1/session.d /usr/share/dbus-1/services -name "*<组件名>*" 2>/dev/null
busctl --user list | grep -i <组件名>
```

### PolicyKit 配置检查

```bash
# 查找组件关联的 PolicyKit action
find /usr/share/polkit-1 -name "*<组件名>*" 2>/dev/null
pkaction | grep -i <组件名>

# 对每个 action 检查 allow_active
pkaction --action-id <action> --verbose | grep "implicit active"
```

### 配置文件权限

```bash
# 检查配置文件是否被普通用户可写
ls -la <配置文件路径>
getfacl <配置文件路径> 2>/dev/null

# 危险信号：
# - 普通用户可写 (e.g., -rw-rw-rw-)
# - 属组为 users 且组可写
# → 配置文件可写 → 注入攻击（修改配置导致服务执行恶意操作）
```

> 本文件是从"入口→攻击面"枚举；若已知疑似 sink 需反查入口，见 SKILL.md「可达性回溯：疑似 sink → 攻击者入口」。

### sudo 权限检查

```bash
# 查看当前用户的 sudo 权限
sudo -l 2>/dev/null

# 危险信号（可被滥用的 sudo 规则）：
# (ALL) NOPASSWD: ALL             → 直接 sudo su
# (root) NOPASSWD: /usr/bin/vim   → sudo vim -c '!sh'
# (root) NOPASSWD: /usr/bin/find  → sudo find . -exec /bin/sh \;
# (root) NOPASSWD: /usr/bin/python → sudo python -c 'import pty;pty.spawn("/bin/bash")'
# (root) NOPASSWD: /usr/bin/apt   → sudo apt update -o APT::Update::Pre-Invoke::=/bin/bash
# (root) SETENV: /path/to/prog    → 可通过环境变量传递 LD_PRELOAD
# 更多参考：https://gtfobins.org/
```

### 定时任务审计

```bash
# 查看系统 cron 任务
cat /etc/crontab
ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/

# 检查 cron 脚本或目录是否可写
find /etc/cron* -writable -type f 2>/dev/null
find /etc/cron* -writable -type d 2>/dev/null  # 目录可写 → 可新建脚本

# 检查 cron 任务中的通配符（tar/rsync 等支持 --checkpoint-action 注入）
grep -R '\*' /etc/crontab /etc/cron.d/ 2>/dev/null
```

### Unix Socket 审计

```bash
# 列出所有 Unix Domain Socket
ss -xlpn 2>/dev/null

# 检查 socket 文件权限（普通用户可写/可连接的 socket）
find /run /var/run /tmp -type s -ls 2>/dev/null

# 尝试连接可疑 socket
nc -U <socket_path> 2>&1
# 普通用户能连接且无认证 → 可能未授权访问
```

### loopback 网络服务审计

```bash
# 列出监听在 127.0.0.1 的服务
ss -tlnp | grep '127.0.0.1'

# 注意：127.0.0.1 "只监听本地"，但本地任何用户都能连接
# 测试这些服务是否有认证
curl http://127.0.0.1:<port>/ 2>&1 | head -20
# 无需认证 → 本地提权攻击面
```

---

## A3：系统状态对比（启服/加载模块前后）

这是发现**隐藏攻击面**的核心方法。很多接口只在服务启动或模块加载后才出现。

### 流程

```bash
# 1. 记录加载前状态
cat /proc/net/netlink > /tmp/before_netlink
ls /sys/kernel/security/ > /tmp/before_secfs
busctl --system list > /tmp/before_dbus
busctl --user list > /tmp/before_user_dbus      # 会话总线（GUI/桌面组件必做）
ss -elnp > /tmp/before_sockets

# 2. 加载组件
# 内核模块：
insmod <模块路径>
# 或守护进程：
systemctl start <服务名>
# 或桌面/GUI 应用：直接以当前用户启动（会话总线服务随启动注册）

# 3. 对比差异
diff /tmp/before_netlink <(cat /proc/net/netlink)
diff /tmp/before_secfs <(ls /sys/kernel/security/)
diff /tmp/before_dbus <(busctl --system list)
diff /tmp/before_user_dbus <(busctl --user list)
diff /tmp/before_sockets <(ss -elnp)

# 4. 清理
rm /tmp/before_*
```

### 五个维度的解读

| 维度 | 命令 | 新出现意味着什么 |
|------|------|----------------|
| netlink | `cat /proc/net/netlink` | 内核模块注册了 netlink 通信接口，用户态可通过 socket 与之交互 |
| securityfs | `ls /sys/kernel/security/` | 内核模块在 securityfs 暴露了接口，读写可能影响安全策略 |
| D-Bus | `busctl --system list` | 守护进程注册了新的 D-Bus 服务，枚举方法并测试授权 |
| 会话总线 | `busctl --user list` | 组件注册了用户总线服务（GUI/桌面应用常见），**默认对同 UID 任意进程开放**；用 `tree` 枚举全部对象路径 |
| 监听端口 | `ss -elnp` | 守护进程开启了监听 socket，检查是否为本地 only、是否有认证 |

### 对新出现的接口做后续测试

- **新 netlink** → 用 Python 构造 netlink 消息测试。**注意格式**：netlink 消息头为 `u32 len, u16 type, u16 flags, u32 seq, u32 pid`，len 必须是 4 字节。常见错误：`struct.pack('HHII', ...)` 把 len 打成 2 字节，内核解析出错误的长度值导致**永久 timeout 无回显**。正确格式：

  ```python
  import socket, struct
  sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, <协议号>)
  sock.bind((0, 0))
  # 正确：len 必须用 I (4字节)，用 = 前缀控制对齐
  msg = struct.pack('=IHHII', 16, type, flags, seq, pid) + payload
  sock.send(msg)
  data = sock.recv(4096)  # 内核返回响应
  ```
- **新 securityfs** → `cat`/`echo` 读写测试权限
- **新 D-Bus 服务（系统总线）** → 进入 D-Bus 驱动模式（模式 C）；用 `busctl tree` 枚举**全部对象路径**，逐路径 `introspect`——根路径只返回 Introspectable/Peer **不等于**无攻击面
- **新会话总线服务** → 同样进入模式 C，但用 `busctl --user` 系列命令；GUI/桌面组件常在此暴露控制接口，且 Qt 应用会自动导出 `org.qtproject.Qt.QWidget`（`close()`/`show()`/`hide()`）等免费接口
- **新监听端口** → `curl`/`nc` 测试是否接受非本地连接

---

## 配置文件权限专项检查

```bash
# 1. 查看配置文件和目录权限
ls -laR <配置目录> 2>/dev/null

# 2. 检查是否有可写的配置文件
find <配置目录> -writable -type f 2>/dev/null

# 3. 检查配置文件的属主和属组
stat <配置文件路径>

# 4. 如果配置目录可写 → 可以创建新配置文件
ls -la <配置目录> | grep '^d' | awk '{print $1, $3, $4, $NF}'

# 5. 测试写入（不实际修改）
touch <配置目录>/test_write 2>&1
rm -f <配置目录>/test_write
```

**判断标准**：
- 普通用户可写配置文件 → 高价值目标，可注入恶意配置
- 配置目录可写 → 可新建配置文件（即使原文件不可写）
- 配置中如果有 `ExecStart`/`command`/`script` 等字段 → 可注入命令
