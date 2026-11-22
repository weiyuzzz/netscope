import { useMemo } from 'react'
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  type Edge as RfEdge,
  type Node as RfNode,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  Activity,
  Cable,
  Globe,
  Laptop,
  List,
  MapPin,
  Network,
  Server,
  ShieldCheck,
  Waypoints,
} from 'lucide-react'
import { useTopologyStore } from '../../stores/liveStores'
import type { EdgeKind, NodeKind, TopologyNode } from '../../types/network'

/** 分层布局（层号 → 视觉层级）。 */
const LAYER: Record<NodeKind, number> = {
  local_computer: 0,
  network_adapter: 1,
  gateway: 1,
  dns_server: 1,
  vpn: 1,
  proxy: 2,
  process: 3,
  domain: 4,
  remote_ip: 4,
  route_hop: 5,
}

const NODE_ICON: Record<NodeKind, typeof Laptop> = {
  local_computer: Laptop,
  network_adapter: Network,
  gateway: Waypoints,
  dns_server: Server,
  process: List,
  domain: Globe,
  remote_ip: Cable,
  proxy: ShieldCheck,
  vpn: ShieldCheck,
  route_hop: MapPin,
}

const NODE_TITLE: Record<NodeKind, string> = {
  local_computer: '本机',
  network_adapter: '网卡',
  gateway: '网关',
  dns_server: 'DNS',
  process: '进程',
  domain: '域名',
  remote_ip: '远端 IP',
  proxy: '代理',
  vpn: 'VPN / 虚拟网卡',
  route_hop: '路由跳点',
}

const EDGE_COLOR: Record<EdgeKind, string> = {
  host_adapter: '#3b82f6',
  adapter_gateway: '#22d3ee',
  adapter_dns: '#22d3ee',
  process_domain: '#a78bfa',
  process_remote_ip: '#3b82f6',
  domain_ip: '#a78bfa',
  process_proxy: '#f59e0b',
  proxy_egress: '#f59e0b',
  route_probe_path: '#64748b',
}

interface NetNodeData extends Record<string, unknown> {
  label: string
  kind: NodeKind
  active: boolean
  sub: string
}

function NetNode({ data }: NodeProps) {
  const d = data as NetNodeData
  const Icon = NODE_ICON[d.kind] ?? Globe
  return (
    <div
      className={`flex min-w-[130px] max-w-[220px] items-center gap-2 rounded-md border px-2.5 py-1.5 ${
        d.active
          ? 'border-ns-border bg-ns-panel'
          : 'border-ns-border/50 bg-ns-panel/60 opacity-60'
      }`}
      title={NODE_TITLE[d.kind]}
    >
      <Handle type="target" position={Position.Left} className="!bg-ns-muted" />
      <Icon
        className={`h-4 w-4 shrink-0 ${
          d.kind === 'proxy' || d.kind === 'vpn'
            ? 'text-ns-purple'
            : d.active
              ? 'text-ns-accent'
              : 'text-ns-muted'
        }`}
      />
      <div className="min-w-0">
        <div className="truncate text-xs font-medium text-ns-text">{d.label}</div>
        {d.sub && <div className="truncate text-[10px] text-ns-muted">{d.sub}</div>}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-ns-muted" />
    </div>
  )
}

const nodeTypes = { net: NetNode }

function hashJitter(id: string): number {
  let h = 0
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) | 0
  return ((h >>> 0) % 80) - 40
}

export interface TopologyFilters {
  search: string
  showProcesses: boolean
  showEndpoints: boolean
  showProxies: boolean
  showVpn: boolean
  showHops: boolean
  protocol: 'all' | 'tcp' | 'udp'
  lowConfidenceOnly: boolean
  hideInactive: boolean
}

interface TopologyCanvasProps {
  filters: TopologyFilters
  onSelect: (id: string | null) => void
  onEdgeSelect?: (id: string | null) => void
}

/** React Flow 拓扑画布（增量数据 + 分层自动布局 + 过滤）。 */
export function TopologyCanvas({ filters, onSelect, onEdgeSelect }: TopologyCanvasProps) {
  const nodes = useTopologyStore((s) => s.nodes)
  const edges = useTopologyStore((s) => s.edges)
  const version = useTopologyStore((s) => s.version)

  const { rfNodes, rfEdges } = useMemo(() => {
    const search = filters.search.trim().toLowerCase()

    const nodeVisible = (n: TopologyNode): boolean => {
      const kind = n.kind
      if (kind === 'process' && !filters.showProcesses) return false
      if ((kind === 'remote_ip' || kind === 'domain') && !filters.showEndpoints) return false
      if (kind === 'proxy' && !filters.showProxies) return false
      if (kind === 'vpn' && !filters.showVpn) return false
      if (kind === 'route_hop' && !filters.showHops) return false
      if (filters.hideInactive && !n.active && kind !== 'local_computer') return false
      if (search && !n.label.toLowerCase().includes(search) && !n.id.toLowerCase().includes(search))
        return false
      return true
    }

    const visibleNodes = Object.values(nodes).filter(nodeVisible)
    const visibleIds = new Set(visibleNodes.map((n) => n.id))

    const visibleEdges = Object.values(edges).filter((e) => {
      if (!visibleIds.has(e.source) || !visibleIds.has(e.target)) return false
      if (filters.hideInactive && !e.active) return false
      if (filters.lowConfidenceOnly) {
        const ev = e.evidence
        if (!ev || (ev !== 'time_window' && ev !== 'dns_only')) return false
      }
      if (filters.protocol !== 'all') {
        if (e.kind === 'process_remote_ip') {
          const proto = (e.data as { protocol?: string } | null)?.protocol
          if (proto && proto !== filters.protocol) return false
        }
      }
      return true
    })

    // 分层布局：保持已出现节点位置稳定，新节点按层排布
    const byLayer = new Map<number, TopologyNode[]>()
    for (const n of visibleNodes) {
      const layer = LAYER[n.kind] ?? 3
      if (!byLayer.has(layer)) byLayer.set(layer, [])
      byLayer.get(layer)!.push(n)
    }

    const positions = new Map<string, { x: number; y: number }>()
    const layerOrder = [...byLayer.keys()].sort((a, b) => a - b)
    let maxPerLayer = 0
    for (const layer of layerOrder) {
      const list = byLayer.get(layer)!
      maxPerLayer = Math.max(maxPerLayer, list.length)
      list.forEach((n, i) => {
        positions.set(n.id, {
          x: i * 210 + 60 + hashJitter(n.id),
          y: layer * 130 + 40,
        })
      })
    }

    const rfNodes: RfNode[] = visibleNodes.map((n) => {
      const pos = positions.get(n.id)!
      const data = (n.data ?? {}) as Record<string, unknown>
      let sub = ''
      if (n.kind === 'process') sub = `PID ${data.pid ?? ''}`
      else if (n.kind === 'vpn') sub = (data.ipv4 as string[])?.[0] ?? ''
      else if (n.kind === 'network_adapter')
        sub = (data.ipv4 as string[])?.[0] ?? ''
      else if (n.kind === 'proxy')
        sub = `${(data as { confidence?: string }).confidence ?? ''}`
      else if (n.kind === 'remote_ip') sub = `:${(data as { port?: number }).port ?? ''}`
      else if (n.kind === 'route_hop') {
        const rtt = (data.rttMs as number[] | undefined)?.[0]
        sub = rtt != null ? `${rtt.toFixed(1)} ms` : (data.hostname as string) ?? ''
      }
      return {
        id: n.id,
        type: 'net',
        position: pos,
        data: { label: n.label, kind: n.kind, active: n.active, sub },
      }
    })

    const rfEdges: RfEdge[] = visibleEdges.map((e) => {
      const inferred =
        e.evidence === 'time_window' || e.evidence === 'dns_only'
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: e.active && (e.kind === 'process_remote_ip' || e.kind === 'proxy_egress'),
        style: {
          stroke: inferred ? '#fbbf24' : e.active ? EDGE_COLOR[e.kind] : '#475569',
          strokeDasharray: inferred || !e.active ? '6 4' : undefined,
          opacity: e.active ? 0.9 : 0.45,
        },
        label: inferred ? '推断' : undefined,
        labelStyle: { fill: '#94a3b8', fontSize: 10 },
      }
    })

    return { rfNodes, rfEdges }
  }, [nodes, edges, version, filters])

  return (
    <div className="h-full w-full" data-testid="topology-canvas">
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.15}
        maxZoom={1.8}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, node) => onSelect(node.id)}
        onEdgeClick={(_, edge) => onEdgeSelect?.(edge.id)}
        onPaneClick={() => {
          onSelect(null)
          onEdgeSelect?.(null)
        }}
        nodesDraggable
        nodesConnectable={false}
      >
        <Background color="#1e293b" gap={22} />
        <Controls
          className="!border-ns-border !bg-ns-panel [&_button]:!border-ns-border [&_button]:!bg-ns-panel [&_button]:!text-ns-muted"
          showInteractive={false}
        />
      </ReactFlow>
      {rfNodes.length === 0 && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-sm text-ns-muted">
          <span className="inline-flex items-center gap-2">
            <Activity className="h-4 w-4" />
            等待采集数据…（调整过滤条件或等待后台采集循环）
          </span>
        </div>
      )}
    </div>
  )
}
