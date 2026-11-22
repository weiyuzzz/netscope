# Npcap 安装与使用说明（NetScope 抓包模块）

## 状态检查

NetScope 启动后在 **Packet Inspector** 页面会自动检测 Npcap：

- **已安装**：显示版本（来自 `pcap_lib_version`），可直接选择网卡开始抓包；
- **未安装**：显示安装指引（本机实测当前未安装时即显示此状态），其余监控功能不受影响。

## 安装步骤

1. 访问 https://npcap.com 下载最新安装包（Npcap x.x.x Installer）；
2. 安装选项建议：
   - ✅ **Install Npcap in WinPcap API-compatible Mode**（必须，wpcap.dll 兼容层）
   - ✅ **Support raw 802.11 traffic**（可选，需要抓 Wi-Fi 管理帧时）
   - ✅ **Admin Only**（推荐保持默认：限制适配器访问为管理员）
3. 安装完成后**重启 NetScope**（重新加载 wpcap.dll）。

## 使用要求

| 功能 | 要求 |
|---|---|
| 检测 / 网卡枚举 | Npcap 已安装 |
| 开始抓包 | Npcap + **管理员权限运行 NetScope**（Admin Only 安装时） |
| PCAP 导出 | 抓包时填写文件名（保存到应用数据目录 `captures/`） |
| UDP/TCP Traceroute | Npcap + 管理员权限（原始发包） |

## 实机验收结果（Npcap 1.90，2026-11-23）

| 验收项 | 结果 |
|---|---|
| 检测与动态加载 | ✅ wpcap.dll 1.90 / libpcap 1.10.7（System32 兼容模式路径） |
| 设备枚举 | ✅ 12 个设备（含物理 Wi-Fi、TUN、VirtualBox、WAN Miniport） |
| 真实抓包（提权） | ✅ Intel Wi-Fi 网卡 **531 包 / 53.8KB**，TCP 解析 497、DNS 元数据 34 |
| 干净退出（验收 12） | ✅ breakloop + 线程 join，状态 Stopped |
| PCAP 导出 | ✅ 66588 字节，文件 magic 验证通过 |
| 时间戳布局 | 实测 Npcap 1.90 pcap_next_ex 返回**经典 32 位 timeval（16 字节头）**，已按实测修正（初版 64-bit time_t 假设错误，由包头字节转储定位） |

提权方式：抓包验收经 UAC 提升后执行（Npcap Admin Only 默认限制适配器访问）。

## 使用注意

- 抓包是**可选模块**，用户主动启用；默认模式为轻量级系统事件采集（不抓包）；
- 支持的限制项：BPF 过滤表达式、最长持续时间（自动停止）、包数上限、字节上限（50MB 默认）；
- 解析范围：Ethernet / IPv4 / IPv6 / TCP（flags、seq/ack）/ UDP / ICMP / DNS（域名与 A/AAAA 应答）/
  TLS 握手元数据（ClientHello 的 SNI）/ QUIC 版本；
- **不解密 TLS 内容**，不做证书注入或中间人攻击；默认不保存载荷（PCAP 导出除外）；
- 停止抓包时通过 `pcap_breakloop` 中断并 join 采集线程，确保干净退出（验收项 12）。
