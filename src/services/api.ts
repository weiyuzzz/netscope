import { invoke } from '@tauri-apps/api/core'
import type {
  CollectionSettings,
  Connection,
  EgressInfo,
  GraphDiff,
  InterfaceRate,
  NetworkQualityPoint,
  ProxyStatusPayload,
  TopologyEdge,
  TopologyNode,
} from '../types/network'
import type { AppInfo } from '../types/app'

/** 应用与系统信息。 */
export function getAppInfo(): Promise<AppInfo> {
  return invoke<AppInfo>('get_app_info')
}

/** 当前活跃连接（TCP + UDP 端点）。 */
export function getConnections(): Promise<Connection[]> {
  return invoke<Connection[]>('get_connections')
}

/** 全量拓扑（初次加载；后续走 topology:diff 增量事件）。 */
export function getTopologyGraph(): Promise<{
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}> {
  return invoke('get_topology_graph')
}

/** 代理状态总览。 */
export function getProxyStatus(): Promise<ProxyStatusPayload> {
  return invoke<ProxyStatusPayload>('get_proxy_status')
}

/** 最近一次接口速率。 */
export function getInterfaceRates(): Promise<InterfaceRate[]> {
  return invoke<InterfaceRate[]>('get_interface_rates')
}

/** 网络质量历史曲线。 */
export function getQualityHistory(limit?: number): Promise<NetworkQualityPoint[]> {
  return invoke<NetworkQualityPoint[]>('get_quality_history', { limit: limit ?? 300 })
}

/** 代理切换历史（proxy_events 表，通用事件行形态）。 */
export interface PersistedEvent {
  timestamp: string
  source: string
  kind: string
  payload: string
}

export function getProxyEventHistory(limit?: number): Promise<PersistedEvent[]> {
  return invoke<PersistedEvent[]>('get_proxy_event_history', { limit: limit ?? 50 })
}

/** 公网出口探测（用户主动触发）。 */
export function probeEgressIp(): Promise<EgressInfo> {
  return invoke<EgressInfo>('probe_egress_ip')
}

export function getCollectionSettings(): Promise<CollectionSettings> {
  return invoke<CollectionSettings>('get_collection_settings')
}

export function setCollectionEnabled(enabled: boolean): Promise<void> {
  return invoke('set_collection_enabled', { enabled })
}

export function setCollectInterval(secs: number): Promise<void> {
  return invoke('set_collect_interval', { secs })
}

/** 清除本地历史数据（保留活跃状态）。 */
export function clearHistory(keepDays?: number): Promise<void> {
  return invoke('clear_history', { keepDays: keepDays ?? 7 })
}

export type { GraphDiff }

// ---- 抓包（Npcap 可选模块） ----
import type {
  CaptureConfig,
  CaptureDevice,
  CaptureStatus,
  FlowSummary,
  HandshakeTiming,
  NpcapStatus,
  PacketInfo,
  PingResult,
  RouteProbe,
  TcpMetricEvent,
} from '../types/diagnostics'

export function getNpcapStatus(): Promise<NpcapStatus> {
  return invoke<NpcapStatus>('npcap_status')
}

export function listCaptureDevices(): Promise<CaptureDevice[]> {
  return invoke<CaptureDevice[]>('list_capture_devices')
}

export function startCapture(
  config: CaptureConfig,
  exportPath?: string | null,
): Promise<CaptureStatus> {
  return invoke<CaptureStatus>('start_capture', {
    config,
    exportPath: exportPath ?? null,
  })
}

export function stopCapture(): Promise<CaptureStatus> {
  return invoke<CaptureStatus>('stop_capture')
}

export function getCaptureStatus(): Promise<CaptureStatus> {
  return invoke<CaptureStatus>('get_capture_status')
}

export function getCapturePackets(max?: number): Promise<PacketInfo[]> {
  return invoke<PacketInfo[]>('get_capture_packets', { max: max ?? 200 })
}

export function getCaptureFlows(): Promise<FlowSummary[]> {
  return invoke<FlowSummary[]>('get_capture_flows')
}

export function takeCaptureMetrics(): Promise<TcpMetricEvent[]> {
  return invoke<TcpMetricEvent[]>('take_capture_metrics')
}

export function takeCaptureHandshakes(): Promise<HandshakeTiming[]> {
  return invoke<HandshakeTiming[]>('take_capture_handshakes')
}

// ---- 诊断 ----
export function runPing(
  target: string,
  count?: number,
  timeoutMs?: number,
): Promise<PingResult> {
  return invoke<PingResult>('run_ping', {
    target,
    count: count ?? 4,
    timeoutMs: timeoutMs ?? 2000,
  })
}

export function runTraceroute(
  target: string,
  protocol?: string,
  maxHops?: number,
  probesPerHop?: number,
  withAsn?: boolean,
): Promise<RouteProbe> {
  return invoke<RouteProbe>('run_traceroute', {
    target,
    protocol: protocol ?? 'icmp',
    maxHops: maxHops ?? 15,
    probesPerHop: probesPerHop ?? 3,
    withAsn: withAsn ?? true,
  })
}

export function asnLookup(ip: string): Promise<string | null> {
  return invoke<string | null>('asn_lookup', { ip })
}

// ---- 第三轮命令 ----
import type {
  AiConfigPayload,
  AiConversation,
  BenchmarkResultR3,
  DiagnosticFinding,
  DiagnosticRuleMeta,
  RecordingSession,
  ReportExportResultR3,
  ReplayPayload,
  RcaReport,
  SessionEvent,
  TimelineEvent,
} from '../types/diagnostics'

export function startRecording(name: string, scopeMode: string, scopeValue: string | null, testKind?: string): Promise<RecordingSession> {
  return invoke('start_recording', { name, scopeMode, scopeValue: scopeValue ?? null, testKind: testKind ?? 'custom' })
}
export function stopRecording(): Promise<Record<string, unknown>> {
  return invoke('stop_recording')
}
export function listSessions(limit?: number): Promise<RecordingSession[]> {
  return invoke('list_sessions', { limit: limit ?? 50 })
}
export function getSessionEvents(sessionId: string, limit?: number): Promise<SessionEvent[]> {
  return invoke('get_session_events', { sessionId, limit: limit ?? 2000 })
}
export function queryTimelineR3(filters: { since?: string; until?: string; kind?: string; source?: string; limit?: number }): Promise<TimelineEvent[]> {
  return invoke('query_timeline', {
    since: filters.since ?? null,
    until: filters.until ?? null,
    kind: filters.kind ?? null,
    source: filters.source ?? null,
    limit: filters.limit ?? 300,
  })
}
export function replayTopology(at: string): Promise<ReplayPayload> {
  return invoke('replay_topology', { at })
}
export function runDiagnostics(minutes?: number): Promise<DiagnosticFinding[]> {
  return invoke('run_diagnostics', { minutes: minutes ?? 10 })
}
export function getFindings(limit?: number): Promise<DiagnosticFinding[]> {
  return invoke('get_findings', { limit: limit ?? 50 })
}
export function getRuleRegistry(): Promise<DiagnosticRuleMeta[]> {
  return invoke('get_rule_registry')
}
export function setRuleEnabled(ruleId: string, enabled: boolean): Promise<void> {
  return invoke('set_rule_enabled', { ruleId, enabled })
}
export function runRca(subject: string, minutes?: number): Promise<RcaReport> {
  return invoke('run_rca', { subject, minutes: minutes ?? 15 })
}
export function runBenchmark(kind: string, targets: string[], opts?: { count?: number; maxBytes?: number; maxSeconds?: number; dnsServers?: string[] }): Promise<BenchmarkResultR3[]> {
  return invoke('run_benchmark', {
    kind,
    targets,
    count: opts?.count ?? null,
    maxBytes: opts?.maxBytes ?? null,
    maxSeconds: opts?.maxSeconds ?? null,
    dnsServers: opts?.dnsServers ?? null,
  })
}
export function getBenchmarks(limit?: number): Promise<BenchmarkResultR3[]> {
  return invoke('get_benchmarks', { limit: limit ?? 50 })
}
export function exportReport(kind: string, minutes?: number, mask?: { localIps: boolean; publicIps: boolean; hostnames: boolean; domains: boolean }): Promise<ReportExportResultR3> {
  return invoke('export_report', {
    kind,
    minutes: minutes ?? 30,
    maskLocalIps: mask?.localIps ?? false,
    maskPublicIps: mask?.publicIps ?? false,
    maskHostnames: mask?.hostnames ?? false,
    maskDomains: mask?.domains ?? false,
  })
}
export function packageDiagnostics(): Promise<ReportExportResultR3> {
  return invoke('package_diagnostics')
}
export function aiAsk(question: string): Promise<AiConversation> {
  return invoke('ai_ask', { question })
}
export function getAiHistory(limit?: number): Promise<AiConversation[]> {
  return invoke('get_ai_history', { limit: limit ?? 30 })
}
export function getAiConfig(): Promise<AiConfigPayload> {
  return invoke('get_ai_config')
}
export function setAiConfig(kind: string, baseUrl: string | null, apiKey: string | null, model: string | null): Promise<void> {
  return invoke('set_ai_config', { kind, baseUrl, apiKey, model })
}

export function compareBenchmarks(kind: string, target: string): Promise<Record<string, unknown>> {
  return invoke('compare_benchmarks', { kind, target })
}
