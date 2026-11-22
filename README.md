# NetScope

Windows 桌面网络监控与可视化诊断工具。实时采集 TCP/UDP 连接、网卡、DNS 事件，关联进程与远端服务器，并以交互式网络拓扑图呈现。

**产品定位：专业网络可观测性与诊断工具。** 所有数据来自真实 Windows 系统采集，不使用模拟数据。

## 技术栈

| 层 | 技术 |
|---|---|
| 桌面框架 | Tauri 2 |
| 后端 | Rust + Tokio + Serde |
| 系统采集 | windows-rs（IP Helper API / GetAdaptersAddresses / 路由表 / ETW） |
| 前端 | React 19 + TypeScript + Vite |
| 拓扑 | @xyflow/react (React Flow) |
| 图表 | Recharts |
| 状态 | Zustand |
| 样式 | Tailwind CSS 4 |
| 存储 | SQLite（rusqlite，Phase 5） |

## 快速开始

前置要求：Rust (stable-msvc)、Node.js ≥ 20、pnpm、VS 2022 BuildTools (C++)、WebView2 Runtime。

```bash
pnpm install
pnpm tauri dev      # 启动桌面应用（开发模式）
```

```bash
pnpm typecheck                                  # 前端类型检查
pnpm build                                      # 前端构建（tsc + vite）
cargo test --manifest-path src-tauri/Cargo.toml # 后端单元测试
cargo build --manifest-path src-tauri/Cargo.toml
pnpm tauri build                                # Windows 安装包（Phase 5）
```

## 文档

- [ARCHITECTURE.md](ARCHITECTURE.md) — 系统架构与模块划分
- [DEVELOPMENT.md](DEVELOPMENT.md) — 开发进度与环境说明
- [docs/COLLECTION.md](docs/COLLECTION.md) — 网络数据采集技术说明（实测结论与限制）
- [docs/NPCAP.md](docs/NPCAP.md) — Npcap 安装与抓包使用说明
- [PRD.md](PRD.md) — 产品需求文档（两轮）

## 阶段计划

- [x] **Phase 0** 项目初始化：Tauri 2 + React + Rust 骨架，目录结构，编译/测试/运行验证
- [x] **Phase 1** 网络采集：网卡、TCP/UDP 连接、PID 关联、DNS 缓存条目、结构化 JSON
- [x] **第二轮** Advanced Monitoring：代理/VPN 智能、Npcap 抓包（可选）、TCP 质量分析、
  高级路由追踪 + ASN、拓扑整合（代理/VPN/RouteHop 节点）、SQLite 持久化
- [x] **第三轮** Intelligent Diagnostics & History：统一事件时间线、会话录制与报告、
  拓扑回放（基于历史事件重建）、16 条规则诊断引擎、RCA 根因关联、质量基准
  （Ping/DNS/TCP/HTTP/下载/上传）、HTML/JSON/PDF 报告导出（脱敏）、AI 助手
  （Provider 可替换，离线证据模式默认）（122 测试全绿）
- [ ] **Phase 2** 数据关联：连接生命周期、DNS↔IP 关联、统一事件模型、拓扑数据生成
- [ ] **Phase 3** 前端拓扑：Overview / Network Map / Connections 接入真实数据实时更新
- [ ] **Phase 4** 诊断：Ping / DNS 测试 / Traceroute / 网关测试
- [ ] **Phase 5** 存储与打包：SQLite 持久化、设置页、Windows 安装包

## 设计原则

1. 真实 Windows 数据采集，禁止模拟数据冒充监控结果
2. 先可靠的数据采集与模型，再可视化
3. 模块化架构，采集层不依赖 UI，拓扑层不依赖 React
4. 数据准确性优先：DNS 解析 ≠ 实际连接，所有关联保留时间戳与依据
5. 不静默修改网络设置 / 防火墙，公网 IP 查询需用户主动触发
