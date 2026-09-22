# PolicyKit 策略授权测试

## 侦察命令

```bash
# 列出所有 PolicyKit action
pkaction

# 查看指定 action 的详细策略
pkaction --action-id <action-id> --verbose

# 查找策略文件位置
find /usr/share/polkit-1 /etc/polkit-1 -name "*.policy" 2>/dev/null

# 查看本地规则
cat /etc/polkit-1/rules.d/*.rules 2>/dev/null
cat /usr/share/polkit-1/rules.d/*.rules 2>/dev/null
```

## PolicyKit 权限模型

PolicyKit 通过 `allow_active` 和 `allow_inactive` 控制权限：

| 配置 | 含义 |
|------|------|
| `yes` | 无条件允许，无需认证 |
| `auth_admin` | 需要管理员密码认证 |
| `auth_admin_keep` | 需要管理员密码，且有时效（默认10分钟） |
| `no` | 无条件拒绝 |

**核心漏洞模式**：`allow_active=yes` 意味着本地活跃会话用户无需密码即可执行特权操作。

## 测试方法

### 1. 策略审计

```bash
# 检查所有 action 的 allow_active 配置
pkaction --verbose | grep -A5 "implicit active"

# 找出 allow_active=yes 的 action
pkaction --verbose | grep -B5 "implicit active:   yes"
```

### 2. 无密码调用测试

```bash
# 尝试以普通用户身份通过 pkexec 调用
pkexec <command>

# 尝试通过 D-Bus 调用（无密码）
busctl --system call <服务> <路径> <接口> <方法> <参数>
```

### 3. 活跃会话检测

```bash
# 检查是否存在本地座位（seat）
loginctl list-sessions --no-legend
loginctl show-session <session-id> -p Type -p Active -p Seat
```

## pkexec 关键用法

pkexec 是 Linux 的"另一种 sudo"，权限判断从 `/etc/sudoers` 移到了 Polkit XML 策略文件。策略文件中写了 `yes`，等同于 sudoers 里写了 `NOPASSWD: ALL`。

```bash
# 策略通过 org.freedesktop.policykit.exec.path 注解指定管控程序
# 只有通过 pkexec 执行该路径时才触发对应策略

# 自动匹配（根据 exec.path 注解查找策略）
pkexec /usr/bin/dnf update

# 显式指定策略 ID — 可以用 A 策略的授权去执行 B 程序！
pkexec --action org.maicss.dnf /usr/bin/bash
# 使用 org.maicss.dnf 的授权规则，但实际执行的是 /usr/bin/bash
```

**漏洞模式**：策略 `allow_active=yes` + `exec.path` 注解存在 → `pkexec <path>` 无需密码 → 等同于 sudo NOPASSWD。

**注意**：D-Bus 服务不需要 `exec.path` 注解。D-Bus 服务进程自己调用 Polkit API 检查权限。

---

## 典型漏洞模式

### 模式 1：allow_active=yes 未授权操作

```xml
<!-- 漏洞策略 -->
<action id="com.example.dangerous-action">
  <defaults>
    <allow_active>yes</allow_active>
  </defaults>
</action>

<!-- 修复后 -->
<action id="com.example.dangerous-action">
  <defaults>
    <allow_active>auth_admin</allow_active>
  </defaults>
</action>
```

### 模式 2：D-Bus 方法 + PolicyKit 联合

当 D-Bus 服务集成了 PolicyKit 检查时：

1. 查看 D-Bus XML Policy 是否允许普通用户调用
2. 查看对应的 PolicyKit action 是否 allow_active=yes
3. 两者都满足 → 未授权访问

### 模式 3：麒麟特有 PolicyKit 操作

```bash
# 查找麒麟特有的 PolicyKit action
pkaction | grep -i kylin
pkaction | grep -i kysec
pkaction | grep -i ukui
pkaction | grep -i kaiming
```

## 验证命令

### 安全机制生效性核验（判"绕过"之前必做）

判定"Polkit 被绕过/未授权"**之前**，先确认 Polkit 在该路径上**确实生效**——否则"无密码调用成功"可能只是"服务根本没调 Polkit"，根因不同（配置缺陷 vs 绕过）：

```bash
# 1. action 存在且本应拦截（implicit_active 非 yes 才算"本应拦截"）
pkaction --action-id <action> --verbose | grep "implicit active"

# 2. 进程是否真的发起 Polkit 鉴权（D-Bus 服务不调用 CheckAuthorization = 未集成 = 无鉴权）
strings <daemon> | grep -iE 'PolicyKit|CheckAuthorization|polkit'   # 无命中 = 未集成

# 3. action 是否对普通调用方本应拦截（pkcheck 模拟，非交互）
pkcheck --action-id <action> --process $$ 2>&1   # rc=2 "requires authentication" = 本应拦截
```

- **未集成/未加载** → 配置缺陷（修：服务端接入 Polkit），**不是**绕过。
- **已集成但仍可越权** → 才是绕过漏洞。

### 业务级验证

```bash
# 验证 PolicyKit 操作是否实际生效
# 根据具体操作类型选择验证命令

# 例：switch_profile 验证
busctl call com.redhat.tuned /Tuned com.redhat.tuned.control active_profile

# 例：用户操作验证
id <username>
grep <username> /etc/passwd
```
