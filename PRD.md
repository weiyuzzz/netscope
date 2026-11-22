# NetScope 产品需求文档（PRD）

> 本文档沉淀 NetScope 两轮产品需求，作为长期产品规格依据。原始 MVP 任务书与二轮升级需求经整理合并于此。

## 产品定位

专业级 Windows 网络可观测性与诊断工具。核心价值：**真实采集、准确关联、诚实标注**。

## 一、MVP（第一轮，已完成 Phase 0-1，本仓库代码现状）

- 模块：Overview / Network Map / Connections / DNS 监控 / Diagnostics / Settings
- 采集：IP Helper API（网卡、TCP/UDP、路由）、进程关联、DNS 缓存条目
- 拓扑：PC → 网卡 → 网关/DNS；进程 → 域名/IP
- 数据准确性规则：DNS 解析 ≠ 连接；关联必带 evidence + 时间戳；UDP 是端点不是连接；推断不冒充事实
- 存储：SQLite（network_interfaces / processes / dns_events / connections / network_events / topology_snapshots / diagnostics / app_settings）

## 二、第二轮：Advanced Network Monitoring

### F1 代理与 VPN 智能（Proxy Intelligence）
- 分机制检测：系统代理（WinInet 注册表）、WinHTTP 代理、HTTP/HTTPS 代理、SOCKS4/5、本地代理服务、TUN 虚拟网卡、VPN 接口、虚拟网卡（Hyper-V/WSL/Tailscale 等）
- 采集：代理地址/端口/进程/PID/状态、虚拟网卡信息、VPN 接口 IP、默认路由变化、实际公网出口 IP（用户触发）、出口 ASN/地理位置（可获取时）
- 代理链路：应用进程 → 本地代理 → 代理服务器 → 目标；或 进程 → TUN → VPN 隧道 → 远端出口；无证据的内部关联不得伪造，推断关系必须带置信度
- 页面：Proxy Analysis（状态/出口 IP/服务器列表/连接情况/分进程使用/VPN 接口/切换历史）
- 数据表：proxy_events / vpn_interfaces

### F2 Npcap 数据包捕获（可选模块）
- 检测安装状态，未装给出明确指引；用户主动启用；可选网卡；启停/恢复；过滤；大小与时长限制；PCAP 导出
- 解析：Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / DNS / TLS 握手元数据（可观察时）/ QUIC 基础元数据（可观察时）
- 不解密 HTTPS，不做证书注入/中间人
- 显示：时间戳、五元组、协议、长度、TCP Flags、所属连接（可靠关联时）；TCP 会话基础统计
- 数据表：packet_captures / packet_summaries

### F3 TCP 网络质量分析（TCP Analyzer）
- 事件：建连/关闭/重传/重复 ACK/RST/超时；RTT 仅在有可靠测量依据时；连接时长与收发字节
- 面板：建连耗时、失败率、重传统计、活跃连接数、上下行流量、延迟趋势
- 明确区分系统级事件与抓包推导指标
- 数据表：tcp_metrics / network_quality

### F4 高级路由追踪（Route Explorer）
- ICMP / UDP / TCP Traceroute，自定义端口/最大跳数/每跳探测次数
- 每跳 IP / RTT / 丢包 / ASN / 地理位置；路由变化对比
- 拓扑中 Route Hop 为独立节点类型；区分真实连接 / 主动探测 / 推断地理
- 数据表：route_probes / route_hops

### F5 拓扑升级
- 新节点：代理、VPN、TUN 接口、路由探测节点；数据包连接关系；网络质量状态；协议样式
- 过滤：按进程/域名/代理/VPN/异常/TCP-UDP；自动布局与分组，避免视觉混乱

### F6 监控与性能
- 多网卡实时流量、每进程流量（有可靠来源时）、连接数趋势、接口状态变化、质量历史曲线
- 后台采集不阻塞 UI；采集开关与性能控制；Npcap 默认不持续抓包

### F7 UI
- 新页面：Proxy Analysis / Packet Inspector / TCP Analytics / Route Explorer
- 全部与 Network Map 数据联动：点击任意连接可查其 DNS、TCP 事件与路由探测信息

## 验收基准（二轮）

系统代理、本地 SOCKS5、TUN 模式、Tailscale 启停、VPN 节点切换、Google/GitHub/YouTube 访问、持续下载、TCP Traceroute、Npcap 抓 DNS/TCP、多网卡、断网恢复、抓包线程退出 —— 十二项场景可观测。

## 交付物

功能代码、数据库迁移、技术文档、自动化测试、Windows 实机测试结果、Npcap 安装使用说明、新功能指南、更新 DEVELOPMENT.md。
