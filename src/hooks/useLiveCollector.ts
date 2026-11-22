import { useEffect } from 'react'
import {
  getConnections,
  getInterfaceRates,
  getProxyStatus,
  getTopologyGraph,
} from '../services/api'
import {
  onConnectionEvent,
  onMetricsTick,
  onTopologyDiff,
} from '../services/events'
import {
  useConnectionsStore,
  useMetricsStore,
  useTopologyStore,
} from '../stores/liveStores'

/** 挂载后订阅全部后台事件并做一次全量初载。 */
export function useLiveCollector(): void {
  const applyDiff = useTopologyStore((s) => s.applyDiff)
  const resetGraph = useTopologyStore((s) => s.reset)
  const applyTick = useMetricsStore((s) => s.applyTick)
  const setAllConnections = useConnectionsStore((s) => s.setAll)
  const applyConnectionEvent = useConnectionsStore((s) => s.applyEvent)

  useEffect(() => {
    let cancelled = false
    const unlisteners: Array<Promise<() => void>> = []

    // 初载：全量拓扑 + 连接 + 代理状态
    void (async () => {
      try {
        const [graph, conns, proxy] = await Promise.all([
          getTopologyGraph(),
          getConnections(),
          getProxyStatus(),
        ])
        if (cancelled) return
        resetGraph(graph.nodes, graph.edges)
        setAllConnections(conns)
        applyTick({
          interfaceRates: await getInterfaceRates(),
          quality: null,
          proxyServers: proxy.servers,
          proxyLinks: proxy.links,
          vpnInterfaces: proxy.vpnInterfaces,
          proxyEvents: [],
          activeProcesses: new Set(conns.map((c) => c.pid)).size,
          connectionCount: conns.length,
          tickCount: 0,
          errors: [],
        })
      } catch (e) {
        // 后端命令失败如实记录（不静默降级为假数据）
        console.error('初载失败', e)
      }
    })()

    unlisteners.push(onTopologyDiff(applyDiff))
    unlisteners.push(onMetricsTick(applyTick))
    unlisteners.push(onConnectionEvent(applyConnectionEvent))

    return () => {
      cancelled = true
      void Promise.all(unlisteners).then((ls) => ls.forEach((fn) => fn()))
    }
  }, [applyDiff, resetGraph, applyTick, setAllConnections, applyConnectionEvent])
}
