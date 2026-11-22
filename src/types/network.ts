/** 与 Rust `models` 对应的前端类型契约（camelCase，serde 一致）。 */

// ---- 连接 ----
export type Protocol = 'tcp' | 'udp'

export type ConnectionState =
  | 'closed'
  | 'listen'
  | 'syn_sent'
  | 'syn_received'
  | 'established'
  | 'fin_wait1'
  | 'fin_wait2'
  | 'close_wait'
  | 'closing'
  | 'last_ack'
  | 'time_wait'
  | 'delete_tcb'
  | 'endpoint'

export interface Endpoint {
  ip: string
  port: number
}

export interface Connection {
  id: string
  pid: number
  processName: string | null
  protocol: Protocol
  local: Endpoint
  remote: Endpoint | null
  state: ConnectionState
  interfaceIndex: number | null
  firstSeen: string
  lastSeen: string
  bytesSent: number
  bytesReceived: number
}

export type LifecycleKind = 'opened' | 'updated' | 'closed'

export interface ConnectionEvent {
  kind: LifecycleKind
  connection: Connection
}

// ---- 拓扑 ----
export type NodeKind =
  | 'local_computer'
  | 'network_adapter'
  | 'gateway'
  | 'dns_server'
  | 'process'
  | 'domain'
  | 'remote_ip'
  | 'proxy'
  | 'vpn'
  | 'route_hop'

export type EdgeKind =
  | 'host_adapter'
  | 'adapter_gateway'
  | 'adapter_dns'
  | 'process_domain'
  | 'process_remote_ip'
  | 'domain_ip'
  | 'process_proxy'
  | 'proxy_egress'
  | 'route_probe_path'

export type CorrelationEvidence =
  | 'dns_then_connect'
  | 'dns_only'
  | 'ptr_lookup'
  | 'time_window'
  | 'probe_observation'

export interface TopologyNode {
  id: string
  kind: NodeKind
  label: string
  firstSeen: string
  lastSeen: string
  active: boolean
  data: Record<string, unknown> | null
}

export interface TopologyEdge {
  id: string
  source: string
  target: string
  kind: EdgeKind
  evidence: CorrelationEvidence | null
  correlatedAt: string | null
  active: boolean
  lastActive: string | null
  data: Record<string, unknown> | null
}

export interface GraphDiff {
  upsertedNodes: TopologyNode[]
  upsertedEdges: TopologyEdge[]
  removedNodeIds: string[]
  removedEdgeIds: string[]
}

// ---- 代理 / VPN ----
export type ProxyMechanism = 'win_inet' | 'win_http' | 'local_listener'
export type ProxyProtocol = 'http' | 'https' | 'socks4' | 'socks5' | 'unknown'
export type Confidence = 'confirmed' | 'inferred' | 'speculative'

export interface ProxyServer {
  id: string
  mechanism: ProxyMechanism
  protocol: ProxyProtocol
  host: string
  port: number
  processName: string | null
  pid: number | null
  source: string
  confidence: Confidence
  firstSeen: string
  lastSeen: string
  active: boolean
}

export interface ProxyLink {
  pid: number
  processName: string | null
  proxyId: string
  evidence: CorrelationEvidence
  confidence: Confidence
  observedConnections: number
  lastSeen: string
}

export type VirtualAdapterKind =
  | 'physical'
  | 'tun'
  | 'tailscale'
  | 'wireguard'
  | 'openvpn_tap'
  | 'hyper_v_switch'
  | 'loopback'
  | 'other_virtual'

export interface VpnInterface {
  ifIndex: number
  kind: VirtualAdapterKind
  friendlyName: string
  description: string
  ipv4Addresses: string[]
  ipv6Addresses: string[]
  isDefaultRouteOwner: boolean
  gatewayOfDefault: string | null
  speedBps: number
  operationalStatus: string
  firstSeen: string
  lastSeen: string
  active: boolean
}

export type ProxyEventKind = 'detected' | 'changed' | 'removed'

export interface ProxyEvent {
  timestamp: string
  kind: ProxyEventKind
  mechanism: ProxyMechanism
  summary: string
  detail: unknown
}

export interface ProxyStatusPayload {
  servers: ProxyServer[]
  links: ProxyLink[]
  vpnInterfaces: VpnInterface[]
  recentEvents: ProxyEvent[]
}

// ---- 指标 ----
export interface InterfaceRate {
  ifIndex: number
  friendlyName: string
  rxBps: number
  txBps: number
  rxTotal: number
  txTotal: number
  operationalStatus: string
}

export interface NetworkQualityPoint {
  timestamp: string
  rxBps: number
  txBps: number
  tcpTotal: number
  tcpEstablished: number
  udpEndpoints: number
  retransmitsRecent: number
  rstRecent: number
  synFailuresRecent: number
}

export interface MetricsTick {
  interfaceRates: InterfaceRate[]
  quality: NetworkQualityPoint | null
  proxyServers: ProxyServer[]
  proxyLinks: ProxyLink[]
  vpnInterfaces: VpnInterface[]
  proxyEvents: ProxyEvent[]
  activeProcesses: number
  connectionCount: number
  tickCount: number
  errors: string[]
}

// ---- 设置 / 出口 ----
export interface CollectionSettings {
  enabled: boolean
  intervalSecs: number
}

export interface EgressInfo {
  timestamp: string | null
  ip: string | null
  asn: string | null
  org: string | null
  country: string | null
  region: string | null
  city: string | null
  source: string | null
  error: string | null
  viaProxy: string | null
}
