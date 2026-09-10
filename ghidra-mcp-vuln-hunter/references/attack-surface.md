# 攻击面获取（Attack Surface）

确定目标暴露了哪些接口/入口。攻击面来源可插拔，**优先使用黑盒模式提供的结果**——攻击面梳理本身不是逆向的主要工作，只有在黑盒未提供时才在二进制内独立梳理。

> 依 SKILL.md ⓪ 环境确认的结论选择模式：真实环境存在 → **模式 A（先 `busctl introspect` 实测，包括具体签名）**；无环境 → 模式 B。静态梳理出的名称/签名与黑盒实测冲突时，**以黑盒为准**（静态常出现接口名与总线名错位、签名多/少一个 `s` 之类偏差）。

## 模式 A：读取黑盒结果（推荐）

直接读取黑盒阶段已产出的攻击面，无需自行枚举：

- 输入：`{服务名, 接口名, 方法名, 对象路径, 方法签名}` 清单（如 `busctl introspect`、`dbus-send` 探测结果）
- 任务：把攻击面清单交给下一步"识别业务接口"，映射到二进制内处理函数

## 模式 B：独立梳理（黑盒未提供时）

在二进制内自行发现攻击面，按目标类型分四类：

### 1. D-Bus 接口

| 操作 | MCP 工具 |
|------|---------|
| 搜索总线名/接口名/对象路径字符串 | `search_strings("org.xxx")`、`list_strings` |
| 定位注册点 | `get_xrefs_to` 找 `g_bus_own_name` / `g_dbus_interface_skeleton_export` 调用 |

线索：`org.*` 总线名、`/org/*` 对象路径、`g-variant` 类型签名。

### 2. netlink family

| 操作 | MCP 工具 |
|------|---------|
| 搜索 family 名称字符串 | `search_strings`（如 family 名、nlmsg 类型名） |
| 定位 socket 创建 | `get_xrefs_to` 找 `socket(AF_NETLINK, ...)` 调用 |
| 协议号常量 | `list_globals` / 搜索 NETLINK_* 常量值 |

线索：`NETLINK_GENERIC`(16)、family 名、nlmsg 结构魔数。

### 3. socket 服务

| 操作 | MCP 工具 |
|------|---------|
| 搜索绑定路径/端口字符串 | `search_strings("/tmp/xxx.sock")`、`search_strings(":port")` |
| 定位监听循环 | `get_xrefs_to` 找 `bind`/`listen`/`accept` 调用 |
| 消息处理函数 | 反编译 accept/recv 循环后的处理分支 |

线索：unix socket 路径、端口号、协议魔数。

### 4. 文件/配置攻击面

| 操作 | MCP 工具 |
|------|---------|
| 搜索配置路径/扩展名 | `search_strings("/etc/xxx")`、`search_strings("*.conf")` |
| 定位解析函数 | `get_xrefs_to` 配置路径字符串 |
| 文件操作函数 | `list_imports` 过滤 `open`/`read`/`stat` |

线索：硬编码路径、配置文件名、格式串（`%s=%s` 等）。

## 产出

攻击面清单：`{接口/入口, 类型, 暴露对象, 相关字符串/地址}`

清单交给第③步"识别业务接口"映射到处理函数。
