# 开发进度文档

> 每个阶段完成后更新本文件：编译、测试、真实数据检查、问题修复。

## 第二轮：Advanced Network Monitoring ✅（2026-11-22）

**目标**：升级为专业级 Windows 网络监控工具（代理/VPN 智能、Npcap 抓包、TCP 质量、高级路由追踪、拓扑整合）。

### 前置缺口补齐（如实记录）

二轮任务书假设"MVP 已完成拓扑与关联"——实际代码中关联层/拓扑层/存储层未实现（Phase 2/3/5 未执行）。
本轮先补齐三层地基，再叠加新功能：

- [x] 存储层：rusqlite(bundled) + user_version 迁移（001 核心 8 表 / 002 二轮 8 表）+ WAL + 保留策略
- [x] 关联层：连接生命周期差分（Opened/Updated/Closed，first_seen 保持，进程名抖动沿用）
- [x] 拓扑层：TopologyGraph + GraphDiff 增量输出 + 分层自动布局数据

### 二轮新功能

- [x] **Proxy Intelligence**（collector/proxy.rs）：WinInet 注册表 / WinHTTP API / 环回监听推断
      （证据分级：已知端口 Inferred / 3+客户端 Speculative / 无证据不标记）/ VPN·TUN·虚拟网卡分类 /
      默认路由归属 / 出口 IP 探测（curl，用户触发）
- [x] **接口流量计数**（GetIfTable2 差分）+ **后台采集循环**（tokio，2s tick，topology:diff /
      metrics:tick / connection:event 三通道事件推送，不阻塞 UI）
- [x] **Npcap 抓包**（collector/capture.rs）：运行时动态加载 wpcap.dll（构建零依赖 SDK），
      协议解析（Eth/IPv4/IPv6/TCP/UDP/ICMP/DNS含压缩指针/TLS SNI/QUIC 版本），
      会话启停（breakloop + join 干净退出）、BPF 过滤、大小/时长/包数限制、PCAP 流式导出、
      流统计 + 重传/RST/建连耗时（SYN→SYN/ACK 观测）
- [x] **TCP Analyzer**：抓包推导指标（重传/RST/建连耗时，来源标注 capture）+
      系统级 SYN 建连失败检测（SYN_SENT 消失且未达 ESTABLISHED）
- [x] **高级 Traceroute**：ICMP 模式（IcmpSendEcho2 TTL 递增，免管理员，实测到达 1.1.1.1）；
      UDP/TCP 模式如实要求 Npcap+管理员（不伪造）；ASN 查询（cymru DNS TXT，实测 AS15169）；
      路由变化对比；RouteHop 节点推入拓扑（evidence=probe_observation）
- [x] **前端整合**：Overview 实时化（速率曲线/网卡表/代理卡）、Connections 实时表
      （搜索/过滤/排序/跳转拓扑）、Network Map（React Flow，自定义节点、过滤、详情面板、
      联动）、Proxy Analysis、Packet Inspector、TCP Analytics、Route Explorer、Settings
      （采集开关/间隔/清除历史）

### 验证结果（真实运行依据）

| 验证项 | 结果 |
|---|---|
| cargo test | ✅ **77 passed / 0 failed**（含真实系统测试：网卡/TCP/UDP/路由/DNS/traceroute/ASN） |
| pnpm build（tsc+vite） | ✅ 无类型错误 |
| 实机 Overview | ✅ 实时速率/连接数/进程数/流量曲线（截图验证） |
| 实机 Connections | ✅ 538 条真实连接，进程/代理环回流量可见（截图验证） |
| 实机代理检测 | ✅ 系统代理 127.0.0.1:12001 (win_inet)、iKuuVPN(TUN, 默认路由)、Tailscale |
| 实机 ICMP traceroute | ✅ 到达 1.1.1.1（单测真实网络验证） |
| 实机 ASN | ✅ 8.8.8.8 → AS15169 (US) |
| SQLite | ✅ 应用数据目录 netscope.db 打开，WAL 活跃写入 |

### 已知限制（如实记录）

1. 本机未安装 Npcap → 抓包/UDP-TCP traceroute 实机验收待用户安装后进行（模块自带检测与指引，
   解析逻辑已由合成帧单测覆盖 9 项）；
2. 连接字节数：连接表无计数来源，置 0（模型保留）；每进程流量需 ETW（可选增强，未实现）；
3. DNS 域名→IP 映射：Win10 19045 缓存不内联 IP（见 docs/COLLECTION.md），映射经主动探测补全；
4. UDP/TCP traceroute 未实现原始发包（需 Npcap，当前如实拒绝执行）；
5. 每连接 DNS/TCP 事件联动（点击连接查 DNS/TCP 事件）部分实现：详情面板支持连接明细，
   DNS 事件与 TCP 事件按 IP 关联展示待深化。

### 交付物

PRD.md（两轮需求汇总）、docs/NPCAP.md（安装使用说明）、docs/COLLECTION.md、
DEVELOPMENT.md（本文件）、ARCHITECTURE.md、自动化测试 77 项、Windows 实机验证记录。

## 第三轮：Intelligent Diagnostics & Network History ✅（2026-11-22）

**目标**：网络事件历史 / 会话录制 / 自动诊断 / 根因分析 / 质量基准 / 报告导出 / AI 助手。

### 完成项

- [x] **迁移 003**（9 张新表）：sessions / session_events / event_timeline / topology_history /
      diagnostic_rules / diagnostic_results / benchmark_results / root_cause_analysis / ai_conversations
- [x] **统一时间线**（collector/timeline.rs）：连接生命周期 / DNS / 代理 / 接口状态 / IP 变化 /
      速率下降 / 默认路由变化 / 质量采样 → 统一事件流（History 页 + 诊断引擎 + 回放数据源）
- [x] **拓扑历史快照**（每 15 tick 落库）+ **Network Replay**（topology/replay.rs：
      快照基底 + 窗口事件重建，测试验证"回放不包含未来状态"）
- [x] **Session Recorder**：录制器（scope: 全部/进程/域名；环境事件总是收录）+ 自动报告
- [x] **诊断规则引擎**（analyzer/rules.rs）：16 条规则（DNS/TCP/接口/代理VPN/质量），
      每条含触发条件/证据/严重度/置信度/影响/可能原因/验证建议；单指标不出确定性根因；
      规则可禁用（diagnostic_rules 表）
- [x] **RCA 根因关联**（analyzer/diagnostics.rs）：DNS/连接/接口/代理/VPN/路由证据链 →
      可能原因（带证据数与置信度）；证据不足时如实声明（不编造）
- [x] **Benchmark**（analyzer/benchmark.rs）：多目标 Ping / DNS Benchmark / TCP 连接基准 /
      HTTP 分段计时 / 下载·上传速度（用户指定目标 + 流量/时间硬上限；真实本地端到端单测）
- [x] **报告导出**（analyzer/report.rs）：HTML（自包含）/ JSON / PDF（Edge 无头打印），
      脱敏（本地 IP / 公网 IP / 主机名 / 域名，含私网 IP 模式扫描兜底）+ 一键打包（报告+数据库备份）
- [x] **AI Assistant**（ai/）：Provider 可替换（离线证据模式=默认 / OpenAI 兼容 API 含本地模型），
      检索层（关键词→按事件类型全量检索，避免高频事件淹没），system prompt 硬性规则
      （不编造/引用来源/区分事实与推测/证据不足说明/不得改配置），会话持久化
- [x] **数据库**：历史清理（保留策略扩展）、拓扑快照降采样（小时级）、事件批量写入、
      VACUUM INTO 备份
- [x] **前端 5 页**：Session Recorder / History Timeline(+Replay 播放/暂停/倍速/拖动) /
      Diagnostics Center / Benchmark / AI Assistant

### 验证结果（真实运行依据）

| 验证项 | 结果 |
|---|---|
| cargo test | ✅ **122 passed / 0 failed**（第三轮新增 45 项，纯函数或真实端到端） |
| 实机时间线积累 | ✅ 运行数分钟即 4047 条事件 / 8 个拓扑快照（db_stats 工具验证） |
| 实机 AI 检索 | ✅ 按类型检索到真实 dns_new 事件 → 离线回答 → 持久化（ai_ask 工具验证） |
| 实机诊断 | ✅ 30 分钟窗口 5000 事件 → 0 条结论（网络正常无误报） |
| 实机 RCA | ✅ 如实声明"证据不足"（验收第 10 项：不编造根因） |
| 报告导出 | ✅ HTML 生成成功（含结论/RCA/时间线），脱敏单测覆盖 |
| Benchmark | ✅ 本地 1MB 下载 / 256KB 上传端到端实测（速度非零），上限收敛 |
| pnpm build | ✅ 无类型错误 |

### 已知限制（如实记录）

1. 每进程字节流量仍需 ETW（未实现）；RST/重传类指标需 Npcap 会话；
2. PDF 导出依赖系统 Edge（缺失时如实报错，可用浏览器打印 HTML 替代）；
3. "数据压缩"实现为拓扑快照小时级降采样 + VACUUM（未做通用事件压缩）；
4. 拓扑回放重建连接/DNS/域名节点；接口与代理节点依赖快照基底（快照间隔 30s）；
5. AI 离线模式为确定性证据摘要（非模型生成）；配置 OpenAI 兼容端点后才有自然语言分析；
   API Key 明文存于本地 SQLite（本机使用场景提示）。

### 第三轮验收补齐（同日，重复任务书触发的缺口闭环）

- [x] **进程启动/退出追踪**（collector/processes.rs，Toolhelp32 快照差分；
      PID 复用视为退出+启动，不合并）→ 时间线事件 process_started/exited → 会话录制内容补全
- [x] **诊断规则 16 → 23 条**：dns.result_change / dns.server_unreachable / iface.flapping /
      proxy.connect_failure / quality.loss_increase / quality.performance_anomaly /
      tcp.port_unreachable（抓包 ICMP type 3 计数，CaptureManager 非破坏性读取）
- [x] **Benchmark 对比**（验收 7）：同目标历史结果对比命令（速度变化% / 延迟变化）+ UI；
      下载/上传速度较上次下降 >50% 自动写入 benchmark_anomaly 时间线（规则联动）
- [x] **UI 联动**（验收要求）：诊断结论点击 → 自动跳转 History 页并回放到结论发生时刻
- [x] **实机验收执行**（examples/acceptance_run.rs，全部走真实代码路径）：

| 场景 | 结果 |
|---|---|
| 1. 录制正常网络访问 | ✅ 真实 TCP 表差分捕获 7 条连接打开事件，10 条事件入库 |
| 2. 录制 DNS 失败 | ✅ 真实探测 127.0.0.1:53 失败录入会话 |
| 5. 连接失败诊断 | ✅ 真实连接失败 + 规则触发 2 条 |
| 6. 回放历史拓扑 | ✅ 真实累积数据重建 **253 节点 / 214 边**（应用 20 条历史事件） |
| 9. AI 查询历史 | ✅ 30198 字回答引用检索证据（离线模式） |
| 10. 无证据不编造 | ✅ RCA 如实声明证据不足（Speculative） |

场景 3（VPN 切换）/ 4（网卡断开恢复）/ 7 部分需真实网络操作，规则引擎已由合成数据单测覆盖，
对比功能已提供（compare_benchmarks + UI）。

### Npcap 安装与抓包实机验收（2026-11-23）

- [x] Npcap 1.90 官方安装包下载 → 交互式提权安装（静默 /S 首次返回码 2，改交互式成功）
- [x] 抓包实机验收通过：531 包 / TCP 497 / DNS 34 / 干净退出 / PCAP 导出 66KB（详见 docs/NPCAP.md）
- [x] 排障记录：pcap_pkthdr 时间戳布局实测修正（32 位 timeval，非 64-bit time_t 假设）；
      抓包线程 panic 由 catch_unwind 捕获并写入 error 字段（不再静默 Running）
- [x] 架构归正：capture.rs 事件推送改为 EventSink 闭包注入（采集层移除 Tauri 依赖，
      example 不再拉入 UI 静态导入——修复了 STATUS_ENTRYPOINT_NOT_FOUND 加载崩溃）
- [x] 进程追踪补入（Toolhelp32 差分 → process_started/exited 事件）
- [x] Windows 安装包构建：**NetScope_0.1.0_x64-setup.exe（3.47 MiB）**，路径 src-tauri/target/release/bundle/nsis/（Release 编译 6m45s，NSIS 打包成功）

## 开发环境

| 组件 | 版本 |
|---|---|
| OS | Windows 10 (10.0.19045 x64) |
| Rust | 1.100.0 stable-x86_64-pc-windows-msvc |
| Node.js / pnpm | 24.14.0 / 10.26.1 |
| MSVC | VS 2022 BuildTools, 14.44.35207 |
| WebView2 Runtime | 157.0.4341.60 |
| Tauri CLI | @tauri-apps/cli 2.12.6 |

## Phase 0 — 项目初始化 ✅（2026-11-22）

**目标**：建立 Tauri 2 + React + Rust 工程骨架，可独立编译、测试、运行。

### 完成项

- [x] 环境检查：Rust/Node/MSVC/WebView2 全部就绪
- [x] 前端骨架：React 19 + TS 7 + Vite 8 + Tailwind 4 + Zustand，深色主题设计令牌
- [x] 前端页面壳：Sidebar / TopBar / Overview（真实后端数据）/ 4 个占位页（如实标注所属阶段）
- [x] 后端骨架：8 个模块目录按任务书第 6 节建立（collector/correlator/topology/probe/analyzer/storage/models/commands）
- [x] 数据模型：connection / interface / process / network_event / topology（含 serde 序列化与单元测试）
- [x] Tauri 命令：`get_app_info`（真实应用与系统信息）
- [x] 图标：脚本生成源图 + `tauri icon` 全平台产出
- [x] 文档：README / ARCHITECTURE / DEVELOPMENT

### 验证结果（真实运行依据）

| 验证项 | 结果 |
|---|---|
| `pnpm build`（tsc + vite） | ✅ 通过，2146 模块，无类型错误 |
| `cargo test` | ✅ 8 passed, 0 failed（编译 2m52s） |
| `pnpm tauri dev` | ✅ netscope.exe 启动，窗口 `NetScope - 网络监控与诊断` 确认出现 |
| 后端日志 | ✅ `INFO netscope_lib: NetScope 后端启动` |
| 进程退出 | ✅ 干净退出，无残留进程 |

### 已知限制

- 网络采集尚未开始（Phase 1），Overview 仅显示应用信息，无模拟指标
- ETW / DNS 事件采集需评估权限模型后实现（Phase 1）
- 依赖 `COMPUTERNAME` 环境变量获取主机名（Phase 1 可换 GetComputerNameW）

### 下阶段入口

Phase 1：在 `Cargo.toml` 添加 `windows` crate（features: `Win32_NetworkManagement_Iphlpapi` 等），
实现 `collector/adapters.rs`、`collector/tcp.rs`、`collector/udp.rs`，输出结构化 JSON 快照并编写测试。

## Phase 1 — 网络采集 ✅（2026-11-22）

**目标**：实现真实 Windows 网络数据采集，输出结构化 JSON，真实数据测试全绿。

### 完成项

- [x] 引入 `windows` crate 0.62.2（features: IpHelper / Ndis / WinSock / Dns / Threading）
- [x] `collector/adapters.rs`：GetAdaptersAddresses 网卡快照（IP/MAC/MTU/速率/DNS/网关/状态）
- [x] `collector/tcp.rs`：GetExtendedTcpTable IPv4+IPv6 连接快照，PID 关联 + 进程名解析
- [x] `collector/udp.rs`：GetExtendedUdpTable 端点快照（state=Endpoint，无远端，严格区分 TCP）
- [x] `collector/routes.rs`：GetBestInterfaceEx 连接归属接口 + GetIpForwardTable2 默认网关
- [x] `collector/dns.rs`：DnsGetCacheDataTable DNS 缓存域名条目（见下"重要发现"）
- [x] `collector/mod.rs`：NetworkSnapshot 聚合快照 + collect_snapshot()（含 limitations 如实标注）
- [x] Tauri 命令：`get_network_snapshot`、`get_dns_cache`（结构化 JSON，camelCase）
- [x] 诊断工具：`cargo run --example dns_cache_dump`（src-tauri 下）
- [x] 技术文档：docs/COLLECTION.md（采集技术说明 v0.1）

### 重要发现（实测，写入 docs/COLLECTION.md）

1. **DNS 缓存不内联 IP（Win10 19045）**：`DnsGetCacheDataTable` 条目 `wDataLength=0`，
   数据区为堆元数据。旧版"从缓存提取 IP"的技巧失效。NetScope 只取可靠的域名+类型，
   域名→IP 映射交由 Phase 2（主动探测 + ETW 可选），拒绝猜测字节布局。
2. **本机运行 fake-IP 代理**：解析结果为 198.18.x.x 合成地址；端到端 DNS 测试相应
   断言在域名级。连接表数据不受代理模式影响（内核真实数据）。
3. windows-rs 0.62 的模块名/字段名与旧版差异（IpHelper 模块、`u.Byte`、`ucLocalAddr`、
   结构体常量不能作 match 模式等）详见 docs/COLLECTION.md §1。

### 验证结果（真实运行依据）

| 验证项 | 结果 |
|---|---|
| `cargo test` | ✅ **23 passed / 0 failed，0 警告**（含 8 项真实系统集成测试） |
| 端到端 TCP | ✅ 测试内创建真实监听端点 → 快照精确捕获 PID/Listen/端口 |
| 端到端 DNS | ✅ 真实解析 www.microsoft.com → 系统缓存观察到该域名 |
| `cargo build`（应用二进制） | ✅ 通过 |
| 真实数据抽查 | ✅ dns_cache_dump 输出真实域名（mshome.net / tail*.ts.net / aliyuncs 等） |

### 已知限制

- 进程字节收发统计：连接表无此数据，Phase 1 置 0（模型保留字段），UI 标注"不可用"
- ETW 实时事件（TCP/IP + DNS-Client）：需管理员；Phase 2+ 作为可选能力，无权限时降级为轮询差分
- 系统进程（PID 4 等）进程名普通权限不可得 → process_name=None，如实标注

### 下阶段入口

Phase 2：`correlator/connection_correlation.rs`（快照差分 → Opened/Updated/Closed 事件，
维护 first_seen/last_seen）、`dns_correlation.rs`（域名↔IP 关联 + 置信度）、
`topology/builder.rs`（增量图构建）。

## Phase 2 — 数据关联（未开始）

## Phase 3 — 前端拓扑（未开始）

## Phase 4 — 诊断（未开始）

## Phase 5 — 存储与打包（未开始）
