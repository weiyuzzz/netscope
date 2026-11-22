import { useEffect } from 'react'
import { useAppStore } from './stores/appStore'
import { useLiveCollector } from './hooks/useLiveCollector'
import { Sidebar } from './components/common/Sidebar'
import { TopBar } from './components/common/TopBar'
import { OverviewPage } from './pages/Overview'
import { NetworkMapPage } from './pages/NetworkMap'
import { ConnectionsPage } from './pages/Connections'
import { ProxyAnalysisPage } from './pages/ProxyAnalysis'
import { PacketInspectorPage } from './pages/PacketInspector'
import { TcpAnalyticsPage } from './pages/TcpAnalytics'
import { RouteExplorerPage } from './pages/RouteExplorer'
import { SessionRecorderPage } from './pages/SessionRecorder'
import { HistoryTimelinePage } from './pages/HistoryTimeline'
import { DiagnosticsCenterPage } from './pages/DiagnosticsCenter'
import { BenchmarkPage } from './pages/Benchmark'
import { AiAssistantPage } from './pages/AiAssistant'
import { SettingsPage } from './pages/Settings'

function renderPage(page: ReturnType<typeof useAppStore.getState>['currentPage'], focus: string | null) {
  switch (page) {
    case 'overview':
      return <OverviewPage />
    case 'network-map':
      return <NetworkMapPage key={focus ?? 'map'} initialSearch={focus ?? ''} />
    case 'connections':
      return <ConnectionsPage />
    case 'proxy-analysis':
      return <ProxyAnalysisPage />
    case 'packet-inspector':
      return <PacketInspectorPage />
    case 'tcp-analytics':
      return <TcpAnalyticsPage />
    case 'route-explorer':
      return <RouteExplorerPage />
    case 'session-recorder':
      return <SessionRecorderPage />
    case 'history':
      return <HistoryTimelinePage />
    case 'benchmark':
      return <BenchmarkPage />
    case 'ai-assistant':
      return <div className="h-full"><AiAssistantPage /></div>
    case 'diagnostics':
      return <DiagnosticsCenterPage />
    case 'settings':
      return <SettingsPage />
  }
}

export default function App() {
  const currentPage = useAppStore((s) => s.currentPage)
  const focusFilter = useAppStore((s) => s.focusFilter)
  const setCollectorStatus = useAppStore((s) => s.setCollectorStatus)

  // 订阅后台采集事件（拓扑 diff / 指标 tick / 连接事件）并初载
  useLiveCollector()

  useEffect(() => {
    // 后端事件到达后标记采集器运行（首个 tick 通常 2s 内）
    const t = window.setTimeout(() => setCollectorStatus('running'), 2500)
    return () => window.clearTimeout(t)
  }, [setCollectorStatus])

  const isFullBleed = currentPage === 'network-map' || currentPage === 'connections'
  return (
    <div className="flex h-full">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main
          className={
            isFullBleed ? 'min-h-0 flex-1 overflow-hidden' : 'min-h-0 flex-1 overflow-auto p-4'
          }
        >
          {renderPage(currentPage, focusFilter)}
        </main>
      </div>
    </div>
  )
}
