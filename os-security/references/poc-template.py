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
  - 六阶段与报告「验证情况」一一对应
  - 验证一律用系统级证据（标记文件 + owner uid / strace），不依赖接口返回值
  - 幂等自拉起前置进程；finally 自清理（还原配置/DB、删标记）
  - 若把载荷**编码进文件名**（如 SQL 注入用 SQLite `char()` 拼接、避开 '/'），注意 Linux 文件名
    成分上限 **255 字节**——超长会 `OSError: File name too long`，需缩短载荷或标记路径
  - **点对点 / 抽象套接字 D-Bus**（服务不挂总线）：填 P2P_ADDR，且**不要**设 DBUS_SESSION_BUS_ADDRESS；
    跨用户验证用 `sudo -u nobody python3 <本脚本>`。注意 **"方法可跨用户调用" ≠ "敏感数据可读 / 状态被改变"**
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
MARKER = "/tmp/poc-marker"                   # 系统级验证标记（换成你的）

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
    """必须在 finally 调用：还原配置、删标记、停掉本次拉起的进程。"""
    try:
        restore_conf()
        for f in (MARKER, CONF_BAK):
            try:
                os.remove(f)
            except OSError:
                pass
        if _started:
            sh(["pkill", "-x", APP_NAME])     # 注意用 -x（精确进程名），勿用 pkill -f（会误杀自身 shell）
    except Exception as e:                    # noqa: BLE001
        print(f"{YELLOW}[!] cleanup 异常：{e}{RESET}")


def main() -> int:
    # ---- 阶段 1 Presence：目标存在性 ----
    step(1, "Presence 目标存在性")
    if not os.path.exists(TARGET_BIN):
        bad(f"主二进制不存在：{TARGET_BIN}")
        return 2
    ok(f"主二进制存在：{TARGET_BIN}")
    if BIN_MD5:
        got = sh(["md5sum", TARGET_BIN]).stdout.split()
        info(f"md5={got[0] if got else '?'}（预期 {BIN_MD5}）")
    backup_conf()

    # ---- 阶段 2 Introspection：特性检查 ----
    step(2, "Introspection 特性检查")
    info("TODO：枚举接口/方法、定位汇点与门控（objdump/nm/strings，见 SKILL.md『可达性回溯』）")

    # ---- 阶段 3 Reachability：可达性 ----
    step(3, "Reachability 可达性")
    if not ensure_process():
        bad("目标未能就绪（进程未起来 / 总线服务未注册）")
        return 2
    info("TODO：以普通用户身份触发入口（busctl / 二进制参数），确认可达")
    if P2P_ADDR:
        info("P2P 服务：用 Gio.DBusConnection.new_for_address_sync(P2P_ADDR) 连接——不要用 busctl")
        info("  连不上若是 ECONNREFUSED = 没有监听者（按需服务可能已空闲自停），属环境问题；")
        info("  它不是'被拒绝'——须重查 systemctl --user is-active / ss -xlnp 后再下结论")

    # ---- 阶段 4 Boundary：权限边界 ----
    step(4, "Boundary 权限边界")
    uid = sh(["grep", "-E", "^Uid", "/proc/self/status"]).stdout.strip().replace("\n", " | ")
    info(uid or "Uid: ?")
    info("TODO：记录目标进程 uid / 能力位 / 权限位（对照步骤 0 基线，判断是否越权）")
    if P2P_ADDR:
        info("4b 对端 uid 校验（P2P 唯一可能的门禁）：")
        info("   静态 objdump -T <bin> | grep -E 'g_credentials_get_unix_user|sd_bus_creds_get_euid'")
        info("        —— 未导入 = 不具备校验能力；日志出现 peer credentials ≠ 做了校验")
        info(f"   动态 换 uid 连接：sudo -u {P2P_OTHER_USER} python3 <本脚本>")
        info("        成功且方法可调 = 跨用户越权成立（CWE-862）")
        info("        Permission denied = 被传输层挡住（文件系统 socket / 0700 目录）→ 边界成立")

    # ---- 阶段 5 Impact：边界突破（系统级验证，不依赖返回值） ----
    step(5, "Impact 边界突破")
    info("TODO：触发汇点。示例手段：")
    info(f"  - 标记文件：写 {MARKER}，核对 owner uid")
    info("  - strace -f -e trace=execve -p <pid>  观察是否真的出现 sh -c / rm / touch")
    for f in (MARKER,):
        try:
            os.remove(f)
        except OSError:
            pass
    # TODO: 在这里调用入口触发漏洞（busctl / subprocess ...）
    time.sleep(2)
    marker_found = os.path.exists(MARKER)
    if marker_found:
        st = os.stat(MARKER)
        ok(f"标记 {MARKER} 已生成 owner_uid={st.st_uid}")
    else:
        bad(f"标记 {MARKER} 未生成")

    # ---- 阶段 6 Cleanup：清理验证 ----
    step(6, "Cleanup 清理验证")
    cleanup()
    ok("已还原配置 / 删除标记")
    return 0 if marker_found else 1


if __name__ == "__main__":
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