import { create } from 'zustand'
import type {
  Connection,
  ConnectionEvent,
  GraphDiff,
  MetricsTick,
  ProxyEvent,
  ProxyLink,
  ProxyServer,
  InterfaceRate,
  NetworkQualityPoint,
  TopologyEdge,
  TopologyNode,
  VpnInterface,
} from '../types/network'

/** 全局实时数据仓库（由后台事件驱动）。 */

interface TopologyState {
  nodes: Record<string, TopologyNode>
  edges: Record<string, TopologyEdge>
  version: number
  applyDiff: (diff: GraphDiff) => void
  reset: (nodes: TopologyNode[], edges: TopologyEdge[]) => void
}

export const useTopologyStore = create<TopologyState>((set) => ({
  nodes: {},
  edges: {},
  version: 0,
  applyDiff: (diff) =>
    set((s) => {
      const nodes = { ...s.nodes }
      for (const n of diff.upsertedNodes) nodes[n.id] = n
      for (const id of diff.removedNodeIds) delete nodes[id]
      const edges = { ...s.edges }
      for (const e of diff.upsertedEdges) edges[e.id] = e
      for (const id of diff.removedEdgeIds) delete edges[id]
      return { nodes, edges, version: s.version + 1 }
    }),
  reset: (nodes, edges) =>
    set(() => ({
      nodes: Object.fromEntries(nodes.map((n) => [n.id, n])),
      edges: Object.fromEntries(edges.map((e) => [e.id, e])),
      version: Date.now(),
    })),
}))

interface MetricsState {
  interfaceRates: InterfaceRate[]
  quality: NetworkQualityPoint | null
  qualityHistory: NetworkQualityPoint[]
  proxyServers: ProxyServer[]
  proxyLinks: ProxyLink[]
  vpnInterfaces: VpnInterface[]
  proxyEvents: ProxyEvent[]
  activeProcesses: number
  connectionCount: number
  collectorErrors: string[]
  tickCount: number
  applyTick: (tick: MetricsTick) => void
}

const MAX_QUALITY_POINTS = 600

export const useMetricsStore = create<MetricsState>((set) => ({
  interfaceRates: [],
  quality: null,
  qualityHistory: [],
  proxyServers: [],
  proxyLinks: [],
  vpnInterfaces: [],
  proxyEvents: [],
  activeProcesses: 0,
  connectionCount: 0,
  collectorErrors: [],
  tickCount: 0,
  applyTick: (tick) =>
    set((s) => {
      const qualityHistory = tick.quality
        ? [...s.qualityHistory, tick.quality].slice(-MAX_QUALITY_POINTS)
        : s.qualityHistory
      return {
        interfaceRates: tick.interfaceRates,
        quality: tick.quality,
        qualityHistory,
        proxyServers: tick.proxyServers,
        proxyLinks: tick.proxyLinks ?? [],
        vpnInterfaces: tick.vpnInterfaces,
        proxyEvents: [...tick.proxyEvents, ...s.proxyEvents].slice(0, 200),
        activeProcesses: tick.activeProcesses,
        connectionCount: tick.connectionCount,
        collectorErrors: tick.errors,
        tickCount: tick.tickCount,
      }
    }),
}))

interface ConnectionsState {
  connections: Record<string, Connection>
  setAll: (list: Connection[]) => void
  applyEvent: (ev: ConnectionEvent) => void
}

export const useConnectionsStore = create<ConnectionsState>((set) => ({
  connections: {},
  setAll: (list) =>
    set(() => ({ connections: Object.fromEntries(list.map((c) => [c.id, c])) })),
  applyEvent: (ev) =>
    set((s) => {
      const connections = { ...s.connections }
      if (ev.kind === 'closed') {
        // 保留最后一次状态 60 秒由 UI 过滤展示？——简化：从活跃表中移除
        delete connections[ev.connection.id]
      } else {
        connections[ev.connection.id] = ev.connection
      }
      return { connections }
    }),
}))
