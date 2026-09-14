#!/usr/bin/env bash
# ghidra-mcp 一键部署/清理脚本（headless 容器 + Python bridge）
#
#   ./deploy-ghidra-mcp.sh                        # 部署（默认二进制目录 $HOME/analysis/bin）
#   ./deploy-ghidra-mcp.sh --data-dir /path/to/bin  # 部署，指定二进制目录
#   ./deploy-ghidra-mcp.sh --clear                 # 清理运行时（容器 + bridge 进程），保留 venv 与仓库
#
# 幂等：已存在的镜像/venv/容器只做启动，不重复下载/安装。
set -uo pipefail

DATA_DIR="${DATA_DIR:-$HOME/analysis/bin}"
BIND="${BIND:-127.0.0.1}"
PORT="${PORT:-8089}"
MCP_PORT="${MCP_PORT:-8081}"
IMAGE="${IMAGE:-clannad1/ghidra-mcp-headless:7.0.0}"
CONTAINER="${CONTAINER:-ghidra}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 解析参数
while [[ $# -gt 0 ]]; do
  case "$1" in
    --data-dir) DATA_DIR="$2"; shift 2;;
    --clear)    CLEAR=1; shift;;
    *) echo "未知参数: $1（用法: $0 [--data-dir DIR] [--clear]）"; exit 1;;
  esac
done

step=0
p()  { step=$((step+1)); echo -e "\n\033[1;36m[$step/6]\033[0m $*"; }
ok()  { echo -e "  \033[1;32m✓\033[0m $*"; }
warn(){ echo -e "  \033[1;33m!\033[0m $*"; }
die() { echo -e "  \033[1;31m✗\033[0m $*" >&2; exit 1; }
dot(){ echo -n "  $* ..."; }
run(){ echo -n "  $* ... "; }
done_(){ echo -e "\033[1;32mdone\033[0m"; }

# ---------- --clear ----------
if [[ "${CLEAR:-0}" == "1" ]]; then
  echo -e "\033[1;36m[清理]\033[0m ghidra-mcp 运行时（保留 venv 与仓库）"
  run "停止 bridge 进程"
  pkill -f "bridge-mcp-ghidra.*--mcp-port ${MCP_PORT}" 2>/dev/null && done_ || { echo "skip"; }
  run "删除容器 $CONTAINER"
  docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER" 2>/dev/null \
    && { docker rm -f "$CONTAINER" >/dev/null; done_; } || { echo "skip"; }
  run "清理 pid/log"
  rm -f "$REPO_DIR/bridge.pid" /tmp/ghidra-mcp-bridge.log 2>/dev/null; done_
  echo -e "\n\033[1;32m清理完成\033[0m。重新部署: $0"
  exit 0
fi

# ---------- 0. 前置检查 ----------
p "前置检查"
run "docker"
command -v docker >/dev/null || die "未安装 docker"
docker info >/dev/null 2>&1 || { systemctl start docker 2>/dev/null || true; docker info >/dev/null 2>&1 || die "docker daemon 不可用"; }
done_
run "python3 / curl"
command -v python3 >/dev/null || die "未安装 python3"
command -v curl >/dev/null || die "未安装 curl"
done_
run "数据目录 $DATA_DIR"
mkdir -p "$DATA_DIR" && done_

# ---------- 1. 镜像 ----------
p "镜像"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  ok "镜像已存在，跳过拉取: $IMAGE"
else
  warn "未配置 registry-mirrors 时国内可能慢"
  run "拉取 $IMAGE"
  docker pull "$IMAGE" && done_ || die "拉取失败"
fi

# ---------- 2. 容器 ----------
p "容器"
cur_src="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER" 2>/dev/null || true)"
cur_cmd="$(docker inspect -f '{{join .Config.Cmd " "}}' "$CONTAINER" 2>/dev/null || true)"
expect_cmd="--bind ${BIND} --port ${PORT}"
cur_state="$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || true)"

if [[ "$cur_src" == "$DATA_DIR" && "$cur_cmd" == "$expect_cmd" ]]; then
  if [[ "$cur_state" == "running" ]]; then
    ok "容器已在运行，复用: $CONTAINER"
  else
    run "启动已有容器"
    docker start "$CONTAINER" >/dev/null && done_ || die "启动失败"
  fi
elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
  warn "容器配置不一致，重建: $CONTAINER"
  docker rm -f "$CONTAINER" >/dev/null
  run "创建并启动容器"
  docker run -d --name "$CONTAINER" --user root --network host --restart unless-stopped \
    --mount "type=bind,src=${DATA_DIR},dst=/data" \
    "$IMAGE" --bind "$BIND" --port "$PORT" >/dev/null && done_ || die "创建失败"
else
  run "创建并启动容器"
  docker run -d --name "$CONTAINER" --user root --network host --restart unless-stopped \
    --mount "type=bind,src=${DATA_DIR},dst=/data" \
    "$IMAGE" --bind "$BIND" --port "$PORT" >/dev/null && done_ || die "创建失败"
fi

# ---------- 3. bridge 安装（幂等） ----------
p "Python bridge"
cd "$REPO_DIR"
if [[ -x .venv/bin/bridge-mcp-ghidra ]] && .venv/bin/pip show ghidra-mcp-bridge >/dev/null 2>&1; then
  ok "bridge 已安装（venv 缓存），跳过"
else
  [[ -d .venv ]] || { run "创建 venv"; python3 -m venv .venv && done_; }
  run "安装 bridge（pip -e .）"
  .venv/bin/pip install -q --upgrade pip 2>/dev/null || true
  .venv/bin/pip install -q -e . 2>/dev/null \
    || { .venv/bin/pip install -q hatchling editables
         .venv/bin/pip install -q -e . --no-build-isolation; } \
    || die "安装失败（网络或构建依赖）"
  done_
fi

# ---------- 4. Ghidra 容器健康检查 ----------
p "Ghidra headless 就绪检查"
for i in $(seq 1 30); do
  if curl -sf -m 3 "http://${BIND}:${PORT}/check_connection" >/dev/null 2>&1; then
    conn="$(curl -sf -m 3 "http://${BIND}:${PORT}/check_connection")"
    ok "连通: $conn"
    break
  fi
  echo -n "."
  sleep 2
  [[ $i -eq 30 ]] && die "Ghidra 未就绪（${BIND}:${PORT}）"
done

# ---------- 5. bridge 启动 ----------
p "MCP bridge"
BRIDGE_LOG="$REPO_DIR/bridge.log"
if [[ -e "$BRIDGE_LOG" ]] && [[ ! -w "$BRIDGE_LOG" ]]; then
  BRIDGE_LOG="/tmp/ghidra-mcp-bridge.log"
  warn "日志不可写，改用 $BRIDGE_LOG"
fi

if pgrep -f "bridge-mcp-ghidra.*--mcp-port ${MCP_PORT}" >/dev/null 2>&1; then
  ok "bridge 已在运行"
  mcp_ok=1
else
  mcp_ok=0
  for attempt in 1 2 3 4 5; do
    pkill -f "bridge-mcp-ghidra.*--mcp-port ${MCP_PORT}" 2>/dev/null || true
    sleep 2
    run "启动 bridge（尝试 $attempt/5）"
    nohup "$REPO_DIR/.venv/bin/bridge-mcp-ghidra" \
      --transport streamable-http \
      --mcp-host 0.0.0.0 --mcp-port "$MCP_PORT" \
      >> "$BRIDGE_LOG" 2>&1 &
    echo $! > "$REPO_DIR/bridge.pid"
    for j in $(seq 1 10); do
      code="$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "http://127.0.0.1:${MCP_PORT}/mcp" \
        -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"deploy-check","version":"1.0"}}}' 2>/dev/null || echo 000)"
      if [[ "$code" == "200" ]]; then
        done_
        ok "MCP 就绪: http://127.0.0.1:${MCP_PORT}/mcp"
        mcp_ok=1
        break
      fi
      echo -n "."
      sleep 3
    done
    [[ $mcp_ok -eq 1 ]] && break
    warn "尝试 $attempt 未就绪"
  done
  [[ $mcp_ok -eq 1 ]] || {
    warn "日志末尾:"
    tail -5 "$BRIDGE_LOG" 2>/dev/null | sed 's/^/    /'
    die "MCP bridge 启动失败。若本机有安全中心（如 KySec），请在安全中心放行: $REPO_DIR/.venv/bin/python3"
  }
fi

# ---------- 6. 摘要 ----------
echo -e "\n\033[1;32m========== 部署完成 ==========\033[0m"
cat <<EOF
Ghidra headless : http://${BIND}:${PORT}  (容器 ${CONTAINER})
MCP bridge      : http://127.0.0.1:${MCP_PORT}/mcp
二进制目录       : ${DATA_DIR} → 容器内 /data
bridge 日志      : ${BRIDGE_LOG}

建议在 agent 的 MCP 配置中加入:
  "ghidra-mcp": { "type": "remote", "url": "http://127.0.0.1:${MCP_PORT}/mcp" }

清理: $0 --clear
EOF
