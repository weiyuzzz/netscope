# NetScope 系统架构

## 总体架构

```
┌─────────────────────────────────────────────────────────┐
│  前端 (React + TS + Vite)                                │
│  pages/           Overview / NetworkMap / Connections /  │
│                   Diagnostics / Settings                 │
│  components/      topology / charts / tables / panels /  │
│                   common                                 │
│  stores/          Zustand 状态                           │
│  services/        Tauri invoke 封装（唯一通信入口）        │
│  types/           与 Rust models 对应的通信契约            │
└────────────────────────┬────────────────────────────────┘
                         │ Tauri Command（结构化 JSON，camelCase）
┌────────────────────────▼────────────────────────────────┐
│  commands/        参数校验与转发，无业务逻辑               │
├─────────────────────────────────────────────────────────┤
│  correlator/      连接生命周期 / 进程 / DNS 关联            │
│  topology/        图增量构建（纯 Rust，不依赖 React）       │
│  analyzer/        诊断规则引擎（不依赖页面组件）             │
│  probe/           Ping / Traceroute / DNS 主动探测         │
│  collector/       Windows 数据采集                        │
│    ├─ adapters   GetAdaptersAddresses                    │
│    ├─ tcp/udp    GetExtendedTcpTable / UdpTable + PID    │
│    ├─ routes     GetIpForwardTable2 / GetBestRoute       │
│    ├─ dns        DNS Client ETW（可选）                   │
│    └─ etw        ETW 实时事件（可选，不可用时降级轮询）      │
│  storage/         SQLite 持久化（Phase 5）                │
│  models/          统一数据模型（各层唯一数据契约）           │
└─────────────────────────────────────────────────────────┘
```

## 数据流

```
Windows API / ETW
      │ 原始快照/事件
      ▼
collector ──► models::NetworkEvent（统一 UTC 时间戳 + 来源标注）
      │
      ▼
correlator（快照对比 → 连接生命周期；DNS↔IP 时间关联，保留 evidence）
      │
      ▼
topology::builder（增量 diff：新增/更新/移除节点与边）
      │                    │
      ▼                    ▼
commands（Tauri 事件/命令）  storage（SQLite，Phase 5）
      │
      ▼
前端 stores（增量更新 React Flow 图，避免整图重建）
```

## 模块约束（强制）

1. **采集层不依赖 UI**：`collector` 不得引用 Tauri 类型。
2. **拓扑构建层不依赖 React**：`topology` 为纯 Rust，前端只消费其输出。
3. **诊断引擎不依赖页面组件**：`analyzer` 独立可测试。
4. **前后端通过明确数据结构通信**：所有跨层结构定义在 `models`（Rust 侧权威）与 `types`（TS 镜像）。
5. **统一时间戳**：全部 UTC RFC3339。
6. **事件来源必须标注**：`EventSource` 是关联置信度的基础。

## 拓扑模型（数据准确性核心）

- 7 类节点：LocalComputer / NetworkAdapter / Gateway / DnsServer / Process / Domain / RemoteIp
- 6 类边：HostAdapter / AdapterGateway / AdapterDns / ProcessDomain / ProcessRemoteIp / DomainIp
- **DomainIp 边强制携带** `evidence`（dns_then_connect / dns_only / ptr_lookup / time_window）与 `correlated_at` 时间戳
- DNS 解析结果 ≠ 实际连接：`dns_only` 边仅为展示，不呈现为真实路径
- 一个 IP 可对应多个域名，一个域名可对应多个 IP（多条边表达）
- 同一进程的多个连接为独立边；不同时间 / 不同端点的连接不得合并（连接 ID 由五元组 + PID 派生）

## 目录结构

见 `src-tauri/src` 与 `src` 下的模块划分，与《MVP 0.1 开发任务书》第 6 节一一对应；各模块文件头部注释描述了实现计划与约束。

## 二轮新增架构（Advanced Monitoring）

- `collector/proxy.rs`  Proxy Intelligence：WinInet / WinHTTP / 监听推断（证据分级）/ VPN 分类 / 接口计数
- `collector/runtime.rs` 后台采集运行时：tick 驱动（生命周期差分 → 速率 → 代理状态机 → 拓扑增量 → 质量点）
- `collector/capture.rs` Npcap 抓包：动态加载 wpcap.dll、协议解析、会话管理、PCAP 导出
- `topology/graph.rs`    TopologyGraph + GraphDiff（前端增量更新，不重建整图）
- `storage/database.rs`  迁移 001（核心 8 表）/ 002（proxy_events / vpn_interfaces / packet_captures /
  packet_summaries / tcp_metrics / route_probes / route_hops / network_quality）
- `probe/ping.rs`        ICMP Ping + ICMP Traceroute（IcmpSendEcho2，免管理员）
- `probe/dns_probe.rs`   DNS 主动探测 + cymru ASN TXT 查询
- 事件通道：topology:diff（拓扑增量）/ metrics:tick（速率/代理/质量）/ connection:event（生命周期）
- 置信度体系：confirmed（注册表/API/明文特征）→ inferred（端口惯例+行为）→ speculative（弱证据）；
  推断关系在拓扑中以黄虚线 + "推断"标签呈现，不冒充确认链路

## 关键设计决策记录

| 决策 | 理由 |
|---|---|
| Tauri CLI 用 npm 包 `@tauri-apps/cli`（预编译二进制） | 免去 `cargo install tauri-cli` 数分钟编译 |
| Tailwind 4 以 `@tailwindcss/vite` 插件接入 | CSS-first 配置，无需 postcss 链 |
| Phase 0 不引入 `windows` / `rusqlite` 依赖 | 各阶段独立可编译，重依赖随对应阶段加入 |
| UDP 记录状态统一为 `Endpoint` | Windows UDP 表仅提供端点，不得误报为已建立连接 |
| Npcap 运行时动态加载 | 构建零依赖 SDK；未安装时优雅降级并给出安装指引 |
| 本地代理推断分级 | 端口惯例≠协议确认；≥3 客户端进程才标记未知端口，无证据不标记 |
| UDP/TCP traceroute 拒绝降级 | 无 Npcap+管理员时如实报错，不伪造探测结果 |
| 图标由脚本生成源图 + `tauri icon` 全平台产出 | 无需外部图像工具，可重复构建 |
