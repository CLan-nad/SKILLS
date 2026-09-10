# D-Bus 接口授权测试

## 侦察命令

```bash
# 列出所有 D-Bus 系统服务
busctl list --system

# 枚举指定服务的所有接口和方法
busctl introspect <服务名> <对象路径>

# 查看服务的 XML Policy 配置
cat /etc/dbus-1/system.d/<服务名>.conf

# 发现服务完整的对象路径树
busctl tree <服务名>

# 查看服务进程信息（PID、UID、可执行文件路径）
busctl status <服务名>
# 输出 PID=1234, UID=0, Command=/usr/libexec/kylin-nm-sysdbus
# → Command 路径用于后续二进制分析（strings/strace/checksec）

# 查看 D-Bus 服务激活文件（服务名 → 二进制映射）
cat /usr/share/dbus-1/services/<服务名>.service
# [D-BUS Service]
# Name=org.kaiming.proxy
# Exec=/opt/kaiming-tools/bin/kaiming-sessionproxy-dbus
```

## D-Bus 安全三层控制

```
调用者 → dbus-daemon (XML Policy: /etc/dbus-1/system.d/*.conf)
              ↓
         服务进程 (polkit 检查 — 可选，很多自研服务未集成)
              ↓
         SELinux/AppArmor (MAC 强制访问控制，最后防线)
```

**关键攻击面**：polkit 是可选的。很多自研 D-Bus 服务未集成 polkit，意味着只要 XML Policy 允许，任何用户都能调用。快速检查：

```bash
cat /etc/dbus-1/system.d/<service>.conf | grep -A5 'context="default"'
sudo -u nobody dbus-send --system --print-reply --dest=<service> <object> <interface>.<method>
```

---

## 白名单管控识别（麒麟 limitCtl）

XML Policy 之外还有第四层管控：dbus-daemon 补丁版 limitCtl 按调用方**进程路径**做白名单。

```bash
# 受控标志：任一存在即受控
ls /etc/dbus-1/conf/<总线名>.limit /etc/kylin-config/basic/<服务>.yaml 2>/dev/null
grep -E '^\[|=' /etc/dbus-1/conf/<总线名>.limit 2>/dev/null   # 看 [whitelist]/[rootcontrol]/[auth]
```

普通用户调用被拒时的报错分层：

| 报错 | 含义 |
|------|------|
| `operation not permitted -- Invalid client identity` | 身份层：cmdline/exe 路径不在 `[whitelist]` |
| `auth forbidden` | auth 层：严格服务校验真实 exe inode 不符，或 `[auth] RootOnly=true` |

- 无任何管控配置的服务 → 直接测未授权调用，不存在绕过问题。
- 确认管控后才按 [deep-exploitation.md](deep-exploitation.md)「D-Bus 管控（白名单）绕过」选方法（LD_PRELOAD 优先）；`RootOnly`/`rootcontrol=on` 客户端侧无解，直接放弃。

---

## 步骤 0：权限基线（必须先做）

在测试任何 D-Bus 方法之前，先建立权限基线：

### 0.1 查看 XML Policy 的默认权限

```bash
# 查看服务的默认访问策略
cat /etc/dbus-1/system.d/<service>.conf | grep -A10 'context="default"'

# deny + 特定用户 allow → 普通用户被拒绝
# allow + 无限制 → 任何用户都能调用
```

### 0.2 查看对应 PolicyKit action（如果有）

```bash
# 查找服务关联的 PolicyKit action
pkaction | grep -i <service>

# 查看 action 的默认权限
pkaction --action-id <action> --verbose | grep implicit
# implicit inactive: yes → 非活跃会话无需认证
# implicit inactive: auth_admin_keep → 需要管理员认证
```

### 0.3 记录基线结论

```
基线结论：[该 D-Bus 方法默认需要认证] / [该方法默认允许普通用户调用]
如果为"默认允许普通用户" + 方法本身为普通用户设计 → 停止测试，判定为非漏洞
如果为"默认需要认证" → 继续测试，验证能否绕过
```

---

## 高危操作关键词映射

**重要前提**：遇到不认识的术语时，先搜索了解其 Linux 背景再定级。关键词匹配不到的才是最容易漏的。

### 直接关键词匹配

| 方法名关键词组合 | 风险 | 对应 Linux 操作 |
|-----------------|------|----------------|
| `clear`/`delete`/`remove`/`reset` + `audit`/`log`/`operations` | **P0** | 清除审计日志 (`truncate /var/log/audit/audit.log`) |
| `delete`/`remove` + `user`/`account` | **P0** | 删除用户 (`userdel`) |
| `disable`/`stop`/`close`/`turnoff` + `security`/`selinux`/`firewall`/`mfa`/`otp`/`verify`/`sign`/`audit` | **P0** | 关闭安全机制 (`setenforce 0`, `systemctl stop firewalld`) |
| `unbind`/`unlink` + `ukey`/`otp`/`mfa`/`token`/`key` | **P0** | 解绑认证设备，绕过 MFA |
| `write`/`create` + `file`/`config`/`system` | **P0** | 写入系统文件 |
| `create` + `user`/`admin`/`root` | **P0** | 创建特权用户 (`useradd`) |
| `set`/`update`/`change`/`modify` + `password`/`config`/`policy`/`uid`/`gid`/`sysctl`/`grub` | **P1** | 修改系统/安全配置 |
| `mount`/`load` + `module`/`driver` | **P1** | 挂载/加载内核模块 (`modprobe`, `mount`) |
| `start`/`restart`/`enable` + `service`/`daemon` | **P2** | 启停服务 |
| `get`/`list`/`query`/`status`/`dump`/`export` + 敏感对象名 | **P3→P1** | 查询类，若返回密码/密钥/令牌则升级为 P1 |

### 麒麟/国产系统特有

| 关键词 | 对应组件 |
|--------|---------|
| `kysec`/`secpolicy` | KYSEC 安全框架 |
| `secadmin`/`audadmin`/`sysadmin` | 三权分立 |
| `ukey`/`otp`/`mfa` | 认证设备 |
| `appwhitelist`/`trustedapp` | 应用白名单 |
| `usbpolicy`/`devicepolicy` | 外设管控 |
| `tcm`/`tpm`/`measure` | 可信度量 |

### 容易被忽略的高危术语（需搜索确认背景）

这些术语看着不敏感但实际都是 root-only 特权操作，遇到必须查：

| 术语 | 实质 | 风险 |
|------|------|------|
| `CGROUP` | 内核 cgroup 资源控制 | 修改可导致 DoS/资源逃逸 |
| `Namespace` | 内核 namespace 隔离 | 修改可导致容器逃逸 |
| `Capability`/`CAP_*` | Linux capabilities 权限模型 | 授予权限可提权 |
| `Seccomp` | 内核 seccomp 沙箱 | 修改可绕过系统调用过滤 |
| `BPF`/`eBPF` | 内核 BPF 虚拟机 | 加载恶意程序可提权 |
| `Netlink` | 内核 netlink 通信 | 可操作网络/路由配置 |
| `SELinux`/`AppArmor` | MAC 强制访问控制 | 关闭即安全机制失效 |
| `Polkit`/`PolicyKit` | 权限授权框架 | 修改规则可提权 |
| `Init`/`systemd` | 系统初始化/服务管理 | 修改 unit 可持久化 |
| `Kernel`/`Module` | 内核/内核模块 | 加载模块可执行任意代码 |

若服务名或方法名包含以上术语但不在直接关键词匹配表中 → **同样按 P0/P1 处理**。

---

## 漏洞模式与测试决策树

### 模式 1：高危操作无鉴权
方法名本身说明其功能属于高危操作（见上表），普通用户直接调用成功即漏洞。

### 模式 2：敏感信息泄露
`Get`/`List`/`Dump`/`Export` 开头的方法可能返回密码、密钥、令牌等敏感数据。

### 测试决策树

```
发现 D-Bus 方法
  │
  ├─ 含 clear/delete/remove/reset? → P0 → 测普通用户能否调用
  ├─ 含 disable/stop/close/turnoff? → P0 → 测是否关闭安全机制
  ├─ 含 unbind/unlink?              → P0 → 测是否解绑认证设备
  ├─ 含 write/create?               → P0 → 测是否写入系统文件
  ├─ 含 set/update/change/modify?   → P1 → 测是否需要鉴权
  └─ 含 get/list/dump/export?       → P3 → 测返回是否含敏感信息
```

---

## 参数签名与注入探测

| 签名 | 含义 | POC 关注点 |
|------|------|-----------|
| `s` | string | 附带基础注入探测 (`"; id; #"`) |
| `as` | string 数组 | 数组元素注入 |
| `i`/`u`/`x` | int/uint/int64 | 边界值 (-1, 0, MAX) |
| `b` | boolean | 翻转测试 |

```bash
# 基础注入探测
string:"\"; id; #\""
string:"| whoami"

# 路径遍历探测
string:"../../../etc/shadow"
```

如果普通用户调用已返回权限错误，注入测试无意义——先确认是否未授权访问。

---

## 验证命令速查

核心原则：**不依赖 D-Bus 返回值验证**，用系统级命令独立确认。

```bash
# --- 审计日志 ---
wc -l /var/log/audit/audit.log          # 行数是否归零
ausearch --format text | wc -l
systemctl status auditd

# --- 安全机制 ---
getenforce                               # SELinux
cat /sys/fs/selinux/enforce
systemctl status firewalld
grep gpgcheck=0 /etc/yum.repos.d/*.repo  # 签名验证是否关闭

# --- 用户管理 ---
id <username>
grep <username> /etc/passwd /etc/shadow
echo "<pwd>" | su - <username> -c "exit"; echo $?

# --- 认证设备 ---
ls -la /etc/ukey/bindings/ /etc/otp/ /var/lib/otp/ 2>/dev/null
grep -r "pam_google_authenticator\|pam_duo" /etc/pam.d/

# --- SSH / PAM 配置 ---
grep "^PasswordAuthentication\|^PermitRootLogin\|^PermitEmptyPasswords" /etc/ssh/sshd_config
cat /etc/pam.d/system-auth

# --- 服务管理 ---
systemctl status <service>
systemctl is-active <service>

# --- 内核参数 ---
sysctl <parameter>
cat /proc/cmdline

# --- 麒麟特有 ---
kysec_get_status 2>/dev/null
cat /proc/kysec/status 2>/dev/null
ls -la /etc/app-whitelist/ 2>/dev/null
```
