# 部署引导（Deployment Guide）

> **这是引导，不是脚本。** 部署结果高度依赖环境（docker 版本、网络可达性、是否已有镜像、MCP 客户端类型），盲抄命令必踩坑。请按当前环境选路线，每一步先自检再继续。
>
> 若你只是想"确认后端在不在"，直接看 [§1](#1-先自检mcp-工具是否已在手)。

## 0. 拓扑与真源

本 skill 的全部工具来自 Ghidra MCP 后端，分三层：

```
MCP 客户端（agent）
   │  stdio（推荐）  或  streamable-http :8081/mcp
   ▼
bridge-mcp-ghidra            ← Python 包 ghidra-mcp-bridge，MCP↔HTTP 薄多路复用器
   │  HTTP 127.0.0.1:8089
   ▼
Ghidra headless 容器          ← Ghidra + GhidraMCP.jar 插件，暴露 224 个 REST 端点
```

- **上游真源**：<https://github.com/bethington/ghidra-mcp>
  - `pyproject.toml` 里 `name = "ghidra-mcp-bridge"`，`[project.scripts] bridge-mcp-ghidra = "bridge_mcp_ghidra.cli:main"`
  - wheel 只打包 `python/bridge_mcp_ghidra`；**仓库根的 `pyproject.toml` 必须存在**（`pip install -e .` 依赖它）
- **版本对应（本文验证过的组合）**：镜像 tag `7.0.0` ↔ bridge `7.0.0` ↔ 镜像内 Ghidra `12.1.2` ↔ 224 REST 端点
- 现成镜像：`clannad1/ghidra-mcp-headless:7.0.0`（Docker Hub）

## 1. 先自检：MCP 工具是否已在手

**先判断，再动手。** 在 agent 里看工具列表：

- `load_program` / `reanalyze` / `decompile_function` 等**可以调用** → 后端已就绪，跳到 [§5](#5-冒烟测试) 做一次冒烟
- **没有这些工具** → 继续往下部署

> ⚠ **"工具看起来缺失"有一半不是真的缺失**，而是 bridge 默认 `--lazy` 只加载 3 个工具组。若你在工具列表里找不到 `get_xrefs_to` / `analyze_dataflow`，先看 [§4.2](#42--工具组不设这个一半工具会消失)，不要急着重新部署。

## 2. 取得 Ghidra headless 镜像

### 路线 1：现成镜像（首选）

```bash
docker pull clannad1/ghidra-mcp-headless:7.0.0
```

体积：压缩层约 822 MB（15 层），展开约 1.5 GB。直连 Docker Hub 不通时给 docker daemon 配代理
（`/etc/systemd/system/docker.service.d/http-proxy.conf`，`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`，然后 `systemctl daemon-reload && systemctl restart docker`）。

**若报 `failed to register layer: archive/tar: invalid tar header` → 不要重试、不要怀疑镜像，走路线 3。**

### 路线 2：从上游自建

```bash
cd <ghidra-mcp 仓库根>
docker build -t ghidra-mcp-headless:7.0.0 -f docker/Dockerfile .
```

代价：拉 `eclipse-temurin:21-jdk`（builder + final 两处）、从 GitHub Releases 下 Ghidra zip（约 400 MB）、Maven 构建 headless assembly。**约 20–40 分钟**，且需 Maven Central 可达。

### 路线 3：pull 失败时的绕行（docker 层解压 bug）

**方法论：先证明镜像无损，再怀疑 docker。** 取证三步（`<layer>` 为 manifest 里最大那一层的 digest）：

```bash
docker manifest inspect clannad1/ghidra-mcp-headless:7.0.0     # 取层 digest 与体积

curl -L -o layer.tar.gz -H "Authorization: Bearer <token>" \
  "https://registry-1.docker.io/v2/clannad1/ghidra-mcp-headless/blobs/<layer>"

sha256sum layer.tar.gz    # 应与 manifest 的 digest 逐字节相同
gzip -t layer.tar.gz      # 压缩流完整
tar tzf layer.tar.gz      # ★ 不要接 head！SIGPIPE 会提前终止 tar，只校验前几条，等于没校验
```

若 sha256 / gzip / tar **全部通过**而 docker 仍报 `invalid tar header` ⇒ 是 **docker 的 Go `archive/tar` 解压问题**（GNU tar 宽容、Go 严格），镜像无罪。改为手动组装再导入：

```bash
mkdir -p /var/tmp/build/rootfs && cd /var/tmp/build
# 逐层下载后，按 manifest 顺序解压
for i in $(seq 0 N); do
  tar --xattrs --xattrs-include='*' --numeric-owner -xzf layer-$i.tar.gz -C rootfs
  # whiteout 语义：.wh.<name> → 删同名项；.wh..wh..opq → 清空所在目录（含删掉 .wh.* 自身）
done

tar --xattrs --xattrs-include='*' --numeric-owner --format=posix \
    -cf rootfs.tar -C rootfs .     # ★ 必须 posix：--xattrs 与 --format=gnu 互斥

docker import \
  --change 'ENTRYPOINT ["/app/entrypoint.sh"]' \
  --change 'CMD ["--port","8089"]' \
  --change 'WORKDIR /app' \
  --change 'USER root' \
  --change 'EXPOSE 8089' \
  --change 'VOLUME ["/data","/projects"]' \
  --change 'ENV JAVA_HOME=/opt/java/openjdk' \
  --change 'ENV GHIDRA_HOME=/opt/ghidra' \
  --change 'ENV GHIDRA_MCP_PORT=8089' \
  --change 'ENV JAVA_OPTS="-Xmx2g -XX:+UseG1GC"' \
  rootfs.tar ghidra-mcp-headless:7.0.0
```

> `docker import` 走的是 `archive.Untar`，输入是重新打包的**规范** tar，因此绕开了层注册路径。
> `--change 'ENV K="v with space"'` 的值含空格**必须加引号**，否则报 `can't find = in "-XX:+UseG1GC"`。
> 工作目录别用 `/tmp`——很多发行版 `/tmp` 是 tmpfs（实测仅 3.7 G），大文件一律放 `/var/tmp`。

## 3. 启动容器

```bash
mkdir -p "${DATA_DIR:-$HOME/analysis/bin}"     # 待分析二进制放这里

docker run -d --name ghidra \
  --user root \
  --network host \
  --restart unless-stopped \
  --mount "type=bind,src=${DATA_DIR:-$HOME/analysis/bin},dst=/data" \
  ghidra-mcp-headless:7.0.0 --bind 127.0.0.1 --port 8089
```

每个 flag 的 why：

| flag | 原因 |
|---|---|
| `--user root` | 现成镜像 config 写着 `User=ghidra`，但**镜像内并没有 `ghidra` 用户**（`/etc/passwd` 只有 `ubuntu`）⇒ 不加会因找不到用户而启动失败 |
| `--network host` | 容器直接用宿主网络，8089 直接就位，免端口映射 |
| `--mount` | 宿主机 `$DATA_DIR` ↔ 容器 `/data` |
| `--restart unless-stopped` | 随 docker daemon 自启；另需 `systemctl enable docker` |

> ⚠ **容器内路径 ≠ 宿主机路径。** 传给 `load_program` 的 `file` 必须是 **`/data/<name>`**。写宿主机路径会报文件不存在——这是最容易踩的坑。

`entrypoint.sh` 是**追加式**解析参数（`ARGS="--port $PORT --bind $BIND_ADDRESS $@"`），容器内默认 `GHIDRA_MCP_BIND_ADDRESS=0.0.0.0`，显式传 `--bind 127.0.0.1` 更安全。

**验证**：

```bash
curl -s http://127.0.0.1:8089/check_connection
# Connection OK - GhidraMCP Headless Server v7.0.0-headless
docker logs ghidra 2>&1 | grep -E 'Registered|HTTP server started'
# Registered 224 REST API endpoints
```

> 走上游官方 `docker-compose.yml` 的话会强制 `GHIDRA_MCP_AUTH_TOKEN=${...:?}`（`SecurityConfig.requireAuthForNonLoopbackBind` 拒绝无 token 的非 loopback 绑定），且 bridge 用 `network_mode: "service:ghidra-mcp"`（因 `validate_server_url()` 拒收非 loopback 的 Ghidra URL）。**本引导的现成镜像路线不需要 token。**

## 4. 安装 bridge 并接入 MCP 客户端

### 4.1 源码就位 + venv

```bash
curl -sL -o gh.tar.gz https://codeload.github.com/bethington/ghidra-mcp/tar.gz/refs/heads/main
tar xzf gh.tar.gz && mv ghidra-mcp-main ~/ghidra-mcp
cd ~/ghidra-mcp
python3 -m venv .venv
.venv/bin/pip install -e .                 # 需访问 PyPI；必要时 export HTTPS_PROXY=http://<proxy>:<port>
.venv/bin/pip show ghidra-mcp-bridge       # Version: 7.0.0
.venv/bin/bridge-mcp-ghidra --help
```

> `pip install -e .` 必须在**仓库根**执行（那里有 `pyproject.toml`）。
> 该包**不在 PyPI**（`pypi.org/pypi/ghidra-mcp-bridge/json` → 404），只能从源码装。

### 4.2 ★ 工具组：不设这个，一半工具会消失

bridge **默认 `--lazy`**，连接时只加载 `program,function,listing` 三组（约 90 个工具）。而本 skill 的调用链分析依赖 `xref` / `analysis` / `headless` 等组 ⇒ **工具映射表里会有一半工具找不到**，表现得像"工具不存在"。

| 方式 | 暴露工具 | 说明 |
|---|---|---|
| 默认（`--lazy`） | ~90 | ❌ 不满足本 skill |
| `--default-groups <组列表>` | 按需 | ✅ **推荐** |
| `--no-lazy` | ~231 | 仅当客户端能承受大量工具声明（个别模型 API 会因声明过多直接 400） |

本 skill 需要的组（覆盖映射表全部工具）：

```
--default-groups analysis,documentation,function,headless,listing,program,xref
```

全部 16 组及工具数（运行时可用 bridge 的 `list_tool_groups()` 工具枚举）：

```
datatype 38 / program 35 / function 28 / analysis 20 / listing 20 / server 16 /
documentation 14 / xref 13 / headless 12 / project 6 / malware 5 / symbol 5 /
comment 4 / utility 4 / emulation 2 / getter 2        默认组 = program,function,listing
```

### 4.3 接入 MCP 客户端（二选一）

#### A. stdio（推荐）

客户端把 bridge 拉起为子进程，无需常驻服务：

```jsonc
{
  "mcp": {
    "ghidra-mcp": {
      "type": "local",
      "command": [
        "/home/<you>/ghidra-mcp/.venv/bin/bridge-mcp-ghidra",
        "--default-groups",
        "analysis,documentation,function,headless,listing,program,xref"
      ],
      "environment": { "GHIDRA_MCP_URL": "http://127.0.0.1:8089" },
      "enabled": true,
      "timeout": 120000
    }
  }
}
```

- 上面是 **mimo** 的 schema（`local` 取 `command[]` + `environment{}`）；Claude Desktop 等用 `mcpServers` + `command`/`args`/`env`
- `command` **必须绝对路径**：客户端解析 `command` 用的是它自己的 PATH
- `timeout` 要调大（部分客户端默认 5 s，而自动分析与反编译是分钟级）

#### B. streamable-http

```bash
cd ~/ghidra-mcp
GHIDRA_MCP_URL=http://127.0.0.1:8089 nohup .venv/bin/bridge-mcp-ghidra \
  --transport streamable-http --mcp-host 0.0.0.0 --mcp-port 8081 \
  --default-groups analysis,documentation,function,headless,listing,program,xref \
  > bridge.log 2>&1 &
```

客户端填 `url: http://127.0.0.1:8081/mcp`（mimo 为 `{"type":"remote","url":...}`，该结构还支持 `headers{}`）。

> ⚠ bridge 启用 **DNS-rebinding 保护**，Host 头只允许 loopback（`127.0.0.1` / `localhost` / `::1`）。用别名访问会被拒；必要时 `GHIDRA_MCP_ALLOWED_HOSTS=<host>` 放宽。
> ⚠ 后台常驻的 bridge 在**某些 agent 执行环境里会被连带 kill**（工具调用超时会杀进程组）。遇到"刚起来就没了"，改用 A。

### 4.4 验证接入

```bash
<mcp-client> mcp list          # 例：mimo mcp list → ✓ ghidra-mcp connected
```

再用客户端或 MCP SDK 列一次工具，确认拿到的是 **149 左右**而不是 90。

## 5. 冒烟测试

走通下面五步即说明后端可用（也顺带验证 §3 的路径约定）：

```
load_program            { file: "/data/<binary>" }   → {"success":true,"language":"x86:LE:64:default"}
reanalyze               {}                           → Auto-analysis completed
get_current_program_info{}                           → function_count / image_base / ...
list_functions          {}                           → [{name,address}, ...]
decompile_function      { functions: "<name>" }      → {"<name>": "<pseudocode>"}
```

## 6. 故障排查速查

| 症状 | 原因 / 处置 |
|---|---|
| pull 报 `failed to register layer: archive/tar: invalid tar header` | docker 的 Go tar 解压问题（镜像无损）。先按 §2 路线 3 三重校验自证，再走 import 绕行 |
| `load_program` 报文件不存在 | 传了宿主机路径。必须 `/data/<name>`（§3 的 ⚠） |
| 只有 ~90 个工具，`get_xrefs_to`/`analyze_dataflow` 找不到 | `--lazy` 默认行为。补 `--default-groups`（§4.2） |
| 容器启动即退出 | 走了官方 compose 却没设 `GHIDRA_MCP_AUTH_TOKEN`；或没用 `--user root` |
| bridge 进程莫名消失 | 后台常驻被 agent 环境连带 kill。改用 stdio（§4.3 A） |
| venv 里的 python 被拦截 | 麒麟等系统的安全中心（KySec）会拦 `venv/bin/python3`，需在安全中心放行 |
| `docker import` 报 `can't find = in "-XX:+..."` | `--change 'ENV K=v'` 的值含空格未加引号 |
| `No space left on device` | 工作目录在 tmpfs 的 `/tmp`。换 `/var/tmp` |
| `tar: --xattrs 只能用于 POSIX 归档中` | `--xattrs` 与 `--format=gnu` 互斥。改 `--format=posix` |
| `tar tzf` 校验"通过"但实际有坏层 | 命令接了 `head`，SIGPIPE 提前终止。去掉 `head` 完整遍历 |