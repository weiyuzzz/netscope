/** 二轮新增：抓包 / 指标 / 诊断类型契约。 */

// ---- Npcap 抓包 ----
export interface NpcapStatus {
  installed: boolean
  version: string | null
  hint: string | null
}

export interface CaptureDevice {
  name: string
  description: string | null
  loopback: boolean
}

export interface CaptureConfig {
  adapter: string
  adapterFriendly: string
  bpfFilter: string | null
  snaplen: number
  maxBytes: number | null
  maxDurationSecs: number | null
  maxPackets: number | null
}

export type CaptureState = 'idle' | 'running' | 'stopped' | 'error'

export interface CaptureStatus {
  state: CaptureState
  config: CaptureConfig | null
  startedAt: string | null
  packets: number
  bytes: number
  lastError: string | null
}

export type IpProtocol = 'icmp' | 'icmp_v6' | 'tcp' | 'udp' | { other: number }

export type TlsStage = 'client_hello' | 'server_hello' | 'other_handshake'

export type PacketMeta =
  | { type: 'none' }
  | { type: 'tcp'; seq: number; ack: number; flags: number; payload_len: number }
  | { type: 'udp'; payload_len: number }
  | { type: 'icmp'; kind: number; code: number }
  | { type: 'dns'; is_response: boolean; domain: string | null; answers: string[] }
  | { type: 'tls'; stage: TlsStage; sni: string | null }
  | { type: 'quic'; version: string | null }

export interface PacketInfo {
  timestamp: string
  srcIp: string | null
  dstIp: string | null
  srcPort: number | null
  dstPort: number | null
  protocol: IpProtocol
  length: number
  meta: PacketMeta
  connectionId: string | null
}

export interface FlowSummary {
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  protocol: IpProtocol
  packets: number
  bytes: number
  firstSeen: string
  lastSeen: string
  synCount: number
  finCount: number
  rstCount: number
}

// ---- TCP 指标 ----
export type MetricSource = 'system' | 'capture'
export type TcpAnomalyKind = 'retransmit' | 'dup_ack' | 'rst' | 'syn_failure' | 'timeout'

export interface TcpMetricEvent {
  timestamp: string
  source: MetricSource
  kind: TcpAnomalyKind
  connectionId: string | null
  srcIp: string | null
  srcPort: number | null
  dstIp: string | null
  dstPort: number | null
  detail: unknown
}

export interface HandshakeTiming {
  timestamp: string
  srcIp: string
  dstIp: string
  dstPort: number
  synToSynAckMs: number
  synToEstablishedMs: number
}

// ---- 诊断 ----
export interface PingReply {
  seq: number
  rttMs: number | null
  status: number
}

export interface PingResult {
  targetIp: string
  sent: number
  received: number
  lossRate: number
  rttMs: number[]
  minRttMs: number | null
  avgRttMs: number | null
  maxRttMs: number | null
  replies: PingReply[]
}

export type TraceProtocol = 'icmp' | 'udp' | 'tcp'
export type RouteHopState = 'replied' | 'no_reply' | 'reached'

export interface RouteHop {
  ttl: number
  state: RouteHopState
  ip: string | null
  rttMs: number[]
  probesSent: number
  hostname: string | null
  asn: string | null
}

export interface RouteProbe {
  id: string
  target: string
  resolvedIp: string | null
  protocol: TraceProtocol
  port: number | null
  maxHops: number
  probesPerHop: number
  startedAt: string
  finishedAt: string | null
  hops: RouteHop[]
  pathChanged: boolean | null
}

export interface DnsProbeResult {
  domain: string
  server: string
  answers: string[]
  elapsedMs: number | null
  error: string | null
  timestamp: string
}

// ---- 第三轮：历史 / 会话 / 诊断 / 基准 / AI ----
export type SessionScope =
  | { mode: 'all' }
  | { mode: 'process'; name: string }
  | { mode: 'domain'; domain: string }

export type SessionStatus = 'recording' | 'completed' | 'cancelled'

export interface RecordingSession {
  id: string
  name: string
  scope: SessionScope
  startedAt: string
  stoppedAt: string | null
  status: SessionStatus
  eventCount: number
  testKind: string
}

export interface SessionEvent {
  sessionId: string
  timestamp: string
  source: string
  kind: string
  summary: string
  payload: unknown
}

export interface TimelineEvent {
  timestamp: string
  source: string
  kind: string
  summary: string
  payload: unknown
}

export type Severity = 'info' | 'warning' | 'critical'
export type Confidence = 'confirmed' | 'inferred' | 'speculative'

export interface EvidenceRef {
  source: string
  timestamp: string
  description: string
}

export interface DiagnosticFinding {
  ruleId: string
  title: string
  severity: Severity
  confidence: Confidence
  detectedAt: string
  impactProcesses: string[]
  impactDomains: string[]
  evidence: EvidenceRef[]
  possibleCauses: string[]
  verification: string[]
}

export interface DiagnosticRuleMeta {
  ruleId: string
  category: string
  title: string
  severity: Severity
  description: string
  enabled: boolean
}

export interface PossibleCause {
  description: string
  confidence: Confidence
  evidence: EvidenceRef[]
}

export interface RcaReport {
  id: string
  createdAt: string
  subject: string
  windowStart: string
  windowEnd: string
  symptom: string
  observations: EvidenceRef[]
  causes: PossibleCause[]
  suggestions: string[]
  findingRuleIds: string[]
}

export type BenchmarkKindStr = 'ping' | 'dns' | 'tcp_connect' | 'http' | 'download' | 'upload'

export interface BenchmarkResultR3 {
  id: string
  kind: BenchmarkKindStr
  target: string
  startedAt: string
  finishedAt: string | null
  interface: string | null
  proxyMode: string | null
  egressIp: string | null
  dnsServer: string | null
  metrics: Record<string, unknown>
  error: string | null
}

export interface ReplayPayload {
  at: string
  appliedEvents: number
  nodes: import('./network').TopologyNode[]
  edges: import('./network').TopologyEdge[]
}

export interface AiConversation {
  id: string
  createdAt: string
  provider: string
  question: string
  answer: string
  evidenceUsed: unknown
}

export interface AiConfigPayload {
  kind: string
  baseUrl: string | null
  model: string | null
  hasApiKey: boolean
}

export interface ReportExportResultR3 {
  path: string
  kind: string
}
