# 网络数据采集技术说明（v0.1 · Phase 1）

> 本文档记录 NetScope 采集层的实现依据、已验证的系统行为与能力边界。所有结论均来自本机实测（Windows 10 19045 x64），非文档转述。

## 1. windows-rs 模块映射（0.62.2 实测）

| API | windows-rs 路径 | 返回类型 |
|---|---|---|
| GetAdaptersAddresses | `Win32::NetworkManagement::IpHelper` | `u32`（WIN32_ERROR 码） |
| GetExtendedTcpTable / GetExtendedUdpTable | `Win32::NetworkManagement::IpHelper` | `u32` |
| GetBestInterfaceEx / GetIpForwardTable2 | `Win32::NetworkManagement::IpHelper` | `u32` / `WIN32_ERROR` |
| MIB_* 结构体、IF_TYPE_*、TCP_TABLE_CLASS | `Win32::NetworkManagement::IpHelper` | — |
| IF_OPER_STATUS 常量（IfOperStatusUp 等） | `Win32::NetworkManagement::Ndis` | 结构体常量 |
| DnsGetCacheDataTable | **未封装**（手写 `#[link(name="dnsapi")]` extern） | `i32` |
| DnsFree / DnsFreeRecordList | `Win32::NetworkManagement::Dns` | — |

经验教训（踩坑记录）：

1. **feature 名称是 `Win32_NetworkManagement_IpHelper`**，不是 `Iphlpapi`。
2. **windows-rs 结构体常量不能用作 match 模式**（会被当作绑定捕获，导致"unreachable pattern"陷阱），必须用相等比较。
3. `IP_ADAPTER_ADDRESSES_LH.IfIndex` 位于匿名联合：`a.Anonymous1.Anonymous.IfIndex`。
4. `IN6_ADDR` 字段名是 `u.Byte`（不是 `S_un.Byte`）；`IN_ADDR` 是 `S_un`。
5. IPv6 行字段名是 `ucLocalAddr`（不是 `LocalAddr`）；`MIB_TCPROW.dwState` 是裸 `u32`。
6. 表类 API 缓冲区含 `i64` 字段，需 8 字节对齐 —— 用 `Vec<u64>` 作缓冲区。
7. TCP/UDP 表端口以网络字节序存放在 DWORD 低 16 位：`u16::from_be((v & 0xffff) as u16)`。
8. `GetAdaptersAddresses` / `GetExtendedTcpTable` 返回裸 `u32` 错误码（不是 `Result`/`WIN32_ERROR`）。

## 2. 已验证的采集能力（全部为真实系统调用，cargo test 覆盖）

| 采集项 | API | 验证方式 |
|---|---|---|
| 网卡快照（名称/类型/状态/MTU/速率/MAC/IP/DNS/网关） | GetAdaptersAddresses（AF_UNSPEC + INCLUDE_GATEWAYS） | 集成测试：枚举非空、Up 接口字段合理 |
| TCP 连接（IPv4+IPv6，含 PID 与进程名） | GetExtendedTcpTable(TCP_TABLE_OWNER_MODULE_ALL) | **端到端**：测试内创建真实监听端点 → 快照精确捕获 PID/状态/端口 |
| UDP 端点（IPv4+IPv6，含 PID） | GetExtendedUdpTable(UDP_TABLE_OWNER_MODULE) | 集成测试：非空、状态=endpoint、无远端字段 |
| 连接归属网卡 | GetBestInterfaceEx（真实路由决策，按远端 IP 缓存） | 集成测试：8.8.8.8 返回有效接口索引 |
| 默认网关（与网卡网关互为校验） | GetIpForwardTable2（0.0.0.0/0、::/0） | 集成测试：联网主机存在默认路由 |
| 进程名 | OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) + QueryFullProcessImageNameW | 端到端：自身进程名解析成功；PID 0 如实返回 None |
| DNS 缓存域名条目 | DnsGetCacheDataTable | **端到端**：真实解析 www.microsoft.com → 域名出现在缓存 |

## 3. DNS 采集：方案评估结论

### 3.1 已实测否定的方案

**DNS 缓存提取 IP**（旧资料常见做法）：在 Win10 19045 上，`DnsGetCacheDataTable`
返回的条目 `wDataLength = 0`，结构体后紧跟堆分配元数据（`LMEM` 标记 + 链表指针），
**记录数据（A/AAAA 的 IP 值）不再内联存放**。旧版 Windows 的内存布局技巧在此失效。
NetScope 明确不从缓存猜测 IP 字节——该路径只能提供「近期解析过的域名 + 类型」。

### 3.2 本机环境特例

本测试机运行 fake-IP 模式的 TUN 代理：系统解析 `www.microsoft.com` 返回
`198.18.x.x` 保留段合成地址，与 DNS 缓存中的记录不一一对应。因此
DNS 缓存端到端测试断言在**域名级**（缓存中存在该域名），不断言 IP 级一致。
NetScope 在此类环境下仍能如实反映连接（连接表来自内核，与代理模式无关）。

### 3.3 域名→IP 映射的正式来源（Phase 2）

1. **DNS 主动探测**（`probe/dns_probe`，Phase 4 提前部分实现）：对关注的域名执行
   `DnsQueryEx`，获得真实的域名→IP 解析结果与响应时间，携带时间戳。
2. **ETW DNS-Client 提供程序**（可选增强）：完整查询事件（域名、结果、DNS 服务器、
   来源进程）。实时 ETW 会话需要管理员权限；作为设置项（Settings: 是否启用 ETW），
   无权限时降级为探测方案。UI 中标注数据来源与置信度。

## 4. 能力与限制总表

| 能力 | 普通权限 | 管理员权限 | 备注 |
|---|---|---|---|
| TCP/UDP/网卡/路由快照 | ✅ | ✅ | 内核表，无需特权 |
| 连接→网卡归属 | ✅ | ✅ | GetBestInterfaceEx |
| 进程名 | 大部分 ✅ | ✅ | 系统进程（PID 4 等）普通权限打不开 → 如实置空，不猜测 |
| 进程字节收发统计 | ❌ | ❌ | 连接表不含字节计数；Phase 2+ 经 ETW/轮询差分估算，当前置 0 并在 UI 标注不可用 |
| DNS 缓存域名条目 | ✅ | ✅ | 仅域名+类型（见 §3.1） |
| DNS 查询事件全量 | ❌ | ✅（ETW） | 实时会话需管理员 |
| 每连接实时事件（ETW TCP/IP） | ❌ | ✅（ETW） | 无 ETW 时用连接表轮询差分（Phase 2 关联层） |

## 5. 数据准确性保障（Phase 1 已落实）

- 连接 ID 由「协议+本地端点+远端端点+PID」派生，跨采样稳定；不同时间/端点的连接绝不合并。
- UDP 记录状态恒为 `Endpoint`，`remote=None`；与 TCP `Established` 严格区分。
- TCP `LISTEN` 行的 `0.0.0.0:0` 远端如实置 `None`，不伪造远端。
- 进程名获取失败时为 `None`（快照 `limitations` 字段统计数量），不猜测归属。
- 所有时间戳统一 UTC RFC3339。
