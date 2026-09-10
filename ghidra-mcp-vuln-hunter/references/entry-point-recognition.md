# 识别业务接口（Entry Point Recognition）

把攻击面清单**映射到二进制内的处理函数**。这是数据流分析的第一步：攻击面回答"目标有什么接口"，这里回答"接口在代码里由哪个函数处理"。

## 核心方法：按目标类型找特定入口

识别业务接口没有万能公式——**关键是先判断目标是什么类型，再用对应类型的特征去找**。不同的目标类型，其入口在代码里有不同的表现形式：

| 目标类型 | 先确认 | 再找什么 |
|---------|--------|---------|
| D-Bus 服务（GDBus/QtDBus） | 用了哪个框架 | 框架特有的 handler 注册/命名/参数特征 |
| 内核 ko 模块 / 驱动 | 注册了 netlink family 还是设备文件 | netlink 协议号 / 设备文件的 ioctl 分发 |
| socket 服务（Unix/TCP） | 监听方式与协议 | accept/recv 循环、消息头解析分支 |
| C/S 程序（命令行工具/守护进程） | 输入口是 argv、stdin、环境变量还是配置文件 | 参数解析函数、读取循环 |
| 其他框架（gRPC/REST/CGI 等） | 用的是什么框架/协议 | 框架的路由/分发机制 |

**关键**：下面的分类只是常见目标的示例，不是完整清单。分析时根据目标实际的框架、协议、输入方式，用领域知识推断"这类目标入口长什么样、该搜什么特征"。**目标是先判断类型，再按类型的特征检索。**

## 1. D-Bus 服务（框架感知）

先确认是 GDBus（GLib 系）还是 QtDBus（Qt 系），特征完全不同。

### GDBus（GLib 系）

| 特征 | 说明 |
|------|------|
| `handle-*` 信号 | `g_signal_connect_data(v1, "handle-xxx", handler, ...)` 注册的 handler |
| 第一参数为指针 | `GDBusMethodInvocation *` 参数 → 极大概率是业务处理器 |
| 注册点反向定位 | `g_bus_own_name` / `g_dbus_interface_skeleton_export` 的 xref 找 handler |
| 类型签名 | `g_variant_new("(iss)")` 推断参数类型 |

识别步骤：
1. `search_strings("方法名")` → 方法名地址
2. `get_xrefs_to(方法名地址)` → 引用函数（区分 code/data 引用，聚焦 code）
3. 对候选函数 `get_function_signature` → 确认第一参数是否为指针（`GDBusMethodInvocation*` 特征）
4. `decompile_function` → 反编译验证是否为业务处理器（有分支/校验/业务日志）

### QtDBus（Qt 系）

| 特征 | 说明 |
|------|------|
| 导出符号 | `QDBusConnection::registerService` / `registerObject` |
| 处理器 | `QDBusAbstractAdaptor` 子类的槽函数 |
| 参数类型 | `QDBusMessage` 参数 |
| 元对象系统 | `QMetaObject` 虚表 / `invokeMethod` 调用点 |

识别步骤：搜接口名/类名字符串 → xref 到注册点 → 从注册点找到 Adaptor 类 → 类的槽函数即业务接口。

### 通用框架特征（符号缺失时）

- 方法名模式：`handle_*`、`method_call`、`on_*`
- 回调指针表：结构体中的函数指针数组（vtable 推断，见 call-chain-analysis.md 逆向技巧）
- `g_signal_connect_data` 等注册函数的 xref 列表

## 2. 内核模块 / 驱动（ko）

目标若是内核 ko 模块，先确认注册了什么：netlink family、设备文件、还是 procfs/sysfs 节点。

### netlink family

| 线索 | 识别方法 |
|------|---------|
| 协议号 | 搜索 `netlink_kernel_create` / socket 创建调用，proto 即 family 号 |
| family 注册 | 搜 family 名字符串 → xref → 注册结构体 |
| genl 消息处理 | `genl_register_family` / 消息分发表（cmd → handler 映射） |

处理函数特征：参数含 `nlmsghdr` / `genlmsghdr` 结构指针，内部按 cmd/type 分发。

### 设备文件（ioctl）

| 线索 | 识别方法 |
|------|---------|
| 设备注册 | `register_chrdev` / `misc_register` → 设备名与主设备号 |
| file_operations | 结构体中的 `.unlocked_ioctl` / `.read` / `.write` 函数指针 |
| ioctl 分发 | ioctl handler 内部按 command 号 switch → 各命令处理函数 |

处理函数特征：`file *` + `unsigned int cmd` + `unsigned long arg` 三参数。

## 3. socket 服务消息循环

| 线索 | 识别方法 |
|------|---------|
| 监听循环 | 反编译 `accept`/`recv` 调用点所在函数 |
| 消息头解析 | 处理循环内按魔数/长度字段分发的分支 |
| 协议魔数 | 搜魔数常量 → xref → 比较点所在函数 |

处理函数特征：接收缓冲区 + 长度字段，内部按消息类型 switch 分发。

## 4. C/S 程序参数入口

| 线索 | 识别方法 |
|------|---------|
| main 函数 | 从 `start`/`_start` 或入口点追踪到 main |
| 参数解析 | main 内 `getopt`/`strcmp` 分支 → 各选项处理函数 |
| 环境变量 | 搜 `getenv` 调用 → 参数来源 |
| stdin 输入 | 搜 `read`/`fgets`/`getline` 调用 → 读取后处理逻辑 |

## 5. 配置文件解析

| 线索 | 识别方法 |
|------|---------|
| 配置路径 | 搜 `/etc/*.conf`、硬编码路径 → xref → 读取函数 |
| 格式串 | 搜 `%s=%s`、`key=value` 格式串 → 解析函数 |
| 行读取 | `fgets`/`getline` 调用点 → 逐行解析循环 |

## 其他框架（扩展）

目标若是 gRPC / REST / CGI / 自定义协议等，思路相同：**先识别框架/协议，再找它的路由、分发、消息解析机制**。用领域知识推断入口的表现形式。

## 产出

入口清单：`{接口, 处理函数地址, 参数签名, 输入来源}`

清单交给第④步"深入分析调用链"进行污点追踪。
