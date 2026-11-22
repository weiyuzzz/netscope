import { useEffect, useState } from 'react'
import { Globe, RefreshCw, ShieldCheck } from 'lucide-react'
import {
  useMetricsStore,
} from '../stores/liveStores'
import { getProxyEventHistory, probeEgressIp, type PersistedEvent } from '../services/api'
import { confidenceLabel, formatDateTime } from '../utils/format'
import type { EgressInfo, ProxyServer } from '../types/network'

const MECHANISM_LABEL: Record<string, string> = {
  win_inet: '系统代理 (WinInet)',
  win_http: 'WinHTTP 代理',
  local_listener: '本地代理服务',
}

const VPN_KIND_LABEL: Record<string, string> = {
  tun: 'TUN 隧道',
  tailscale: 'Tailscale',
  wireguard: 'WireGuard',
  openvpn_tap: 'OpenVPN TAP',
  hyper_v_switch: 'Hyper-V / WSL 虚拟交换机',
  loopback: '回环',
  other_virtual: '其他虚拟网卡',
}

function ProxyCard({ server }: { server: ProxyServer }) {
  const conf = confidenceLabel(server.confidence)
  return (
    <div className="rounded-lg border border-ns-border bg-ns-bg p-3 text-xs">
      <div className="flex items-center justify-between">
        <span className="font-mono text-sm text-ns-text">
          {server.host}:{server.port}
        </span>
        <span className={`rounded px-1.5 py-0.5 text-[10px] ${conf.cls} bg-ns-panel`}>
          {conf.label}
        </span>
      </div>
      <div className="mt-1.5 space-y-0.5 text-ns-muted">
        <div>机制：{MECHANISM_LABEL[server.mechanism] ?? server.mechanism}</div>
        <div>协议：{server.protocol.toUpperCase()}</div>
        {server.processName && (
          <div>
            进程：{server.processName}
            {server.pid != null && ` (PID ${server.pid})`}
          </div>
        )}
        <div className="break-all">依据：{server.source}</div>
        <div>最近确认：{formatDateTime(server.lastSeen)}</div>
      </div>
    </div>
  )
}

/** Proxy Analysis：代理 / VPN 状态、使用情况、出口 IP、切换历史。 */
export function ProxyAnalysisPage() {
  const servers = useMetricsStore((s) => s.proxyServers)
  const links = useMetricsStore((s) => s.proxyLinks)
  const vpn = useMetricsStore((s) => s.vpnInterfaces)
  const liveEvents = useMetricsStore((s) => s.proxyEvents)
  const [egress, setEgress] = useState<EgressInfo | null>(null)
  const [probing, setProbing] = useState(false)
  const [history, setHistory] = useState<PersistedEvent[]>([])

  useEffect(() => {
    void getProxyEventHistory(50)
      .then((rows: PersistedEvent[]) => setHistory(rows))
      .catch(() => setHistory([]))
  }, [liveEvents.length])

  const probe = async () => {
    setProbing(true)
    try {
      setEgress(await probeEgressIp())
    } finally {
      setProbing(false)
    }
  }

  const systemServers = servers.filter((s) => s.mechanism === 'win_inet')
  const winhttp = servers.filter((s) => s.mechanism === 'win_http')
  const localServers = servers.filter((s) => s.mechanism === 'local_listener')
  const activeVpn = vpn.filter((v) => v.active && v.kind !== 'loopback')

  return (
    <div className="mx-auto max-w-6xl space-y-4 pb-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Proxy Analysis</h1>
        <button
          onClick={() => void probe()}
          disabled={probing}
          className="inline-flex items-center gap-1.5 rounded-md border border-ns-accent/50 bg-ns-accent/10 px-3 py-1.5 text-xs text-ns-accent hover:bg-ns-accent/20 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${probing ? 'animate-spin' : ''}`} />
          {probing ? '探测中…' : '探测公网出口 IP（主动触发）'}
        </button>
      </div>

      {egress && (
        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-2 flex items-center gap-1.5 text-sm font-medium text-ns-accent">
            <Globe className="h-4 w-4" /> 公网出口（{egress.source ?? '未获取'}）
          </h2>
          {egress.error ? (
            <p className="text-xs text-ns-error">探测失败：{egress.error}</p>
          ) : (
            <div className="grid grid-cols-2 gap-1.5 text-xs sm:grid-cols-3">
              <div><span className="text-ns-muted">出口 IP：</span><span className="font-mono text-ns-text">{egress.ip ?? '-'}</span></div>
              <div><span className="text-ns-muted">ASN：</span><span className="text-ns-text">{egress.asn ?? '-'}</span></div>
              <div><span className="text-ns-muted">组织：</span><span className="text-ns-text">{egress.org ?? '-'}</span></div>
              <div><span className="text-ns-muted">国家：</span><span className="text-ns-text">{egress.country ?? '-'}</span></div>
              <div><span className="text-ns-muted">地区：</span><span className="text-ns-text">{egress.region ?? '-'}</span></div>
              <div><span className="text-ns-muted">城市：</span><span className="text-ns-text">{egress.city ?? '-'}</span></div>
            </div>
          )}
          <p className="mt-2 text-[10px] text-ns-muted">
            仅在你点击时发起探测，不会后台轮询。经代理环境时结果反映代理出口而非本机 ISP。
          </p>
        </section>
      )}

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 flex items-center gap-1.5 text-sm font-medium text-ns-accent">
          <ShieldCheck className="h-4 w-4 text-ns-purple" /> 代理服务（分机制）
        </h2>
        {servers.length === 0 ? (
          <p className="text-xs text-ns-muted">
            当前未检测到任何代理机制。系统代理、WinHTTP、本地监听三类分别检测。
          </p>
        ) : (
          <div className="space-y-3">
            {[
              { title: '系统代理 (WinInet 注册表)', list: systemServers },
              { title: 'WinHTTP 默认代理', list: winhttp },
              { title: '本地代理服务（监听推断）', list: localServers },
            ]
              .filter((g) => g.list.length > 0)
              .map((group) => (
                <div key={group.title}>
                  <div className="mb-1.5 text-xs font-medium text-ns-muted">{group.title}</div>
                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
                    {group.list.map((s) => (
                      <ProxyCard key={s.id} server={s} />
                    ))}
                  </div>
                </div>
              ))}
          </div>
        )}
      </section>

      {links.length > 0 && (
        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-3 text-sm font-medium text-ns-accent">进程代理使用情况（推断链路）</h2>
          <table className="w-full text-xs">
            <thead className="text-ns-muted">
              <tr>
                <th className="pb-1.5 text-left font-medium">进程</th>
                <th className="pb-1.5 text-left font-medium">PID</th>
                <th className="pb-1.5 text-left font-medium">代理</th>
                <th className="pb-1.5 text-right font-medium">观测连接数</th>
                <th className="pb-1.5 text-left font-medium">置信度</th>
              </tr>
            </thead>
            <tbody>
              {links.map((l) => {
                const conf = confidenceLabel(l.confidence)
                const target = servers.find((s) => s.id === l.proxyId)
                return (
                  <tr key={`${l.pid}:${l.proxyId}`} className="border-t border-ns-border/60">
                    <td className="py-1.5 text-ns-text">{l.processName ?? `PID ${l.pid}`}</td>
                    <td className="py-1.5 font-mono text-ns-muted">{l.pid}</td>
                    <td className="py-1.5 font-mono text-ns-text">
                      {target ? `${target.host}:${target.port}` : l.proxyId}
                    </td>
                    <td className="py-1.5 text-right text-ns-muted">{l.observedConnections}</td>
                    <td className={`py-1.5 ${conf.cls}`}>{conf.label}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </section>
      )}

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">VPN / 虚拟网卡</h2>
        {activeVpn.length === 0 ? (
          <p className="text-xs text-ns-muted">当前无活跃的 VPN / 虚拟网卡。</p>
        ) : (
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {activeVpn.map((v) => (
              <div key={v.ifIndex} className="rounded-lg border border-ns-border bg-ns-bg p-3 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-ns-text">{v.friendlyName}</span>
                  <span className="rounded bg-ns-purple/15 px-1.5 py-0.5 text-[10px] text-ns-purple">
                    {VPN_KIND_LABEL[v.kind] ?? v.kind}
                  </span>
                </div>
                <div className="mt-1.5 space-y-0.5 text-ns-muted">
                  <div className="break-all">描述：{v.description}</div>
                  <div>IPv4：{v.ipv4Addresses.join(', ') || '-'}</div>
                  <div>
                    默认路由：
                    {v.isDefaultRouteOwner
                      ? `是（网关 ${v.gatewayOfDefault ?? '-'}）`
                      : '否'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">代理切换历史</h2>
        {history.length === 0 && liveEvents.length === 0 ? (
          <p className="text-xs text-ns-muted">暂无代理变化事件。</p>
        ) : (
          <div className="max-h-64 space-y-1 overflow-auto">
            {liveEvents.map((e, i) => (
              <div key={`live-${i}`} className="rounded border border-ns-border bg-ns-bg px-2 py-1 text-xs">
                <span className="mr-2 font-mono text-ns-muted">{formatDateTime(e.timestamp)}</span>
                <span
                  className={
                    e.kind === 'removed'
                      ? 'text-ns-error'
                      : e.kind === 'changed'
                        ? 'text-ns-warn'
                        : 'text-ns-ok'
                  }
                >
                  {e.kind}
                </span>
                <span className="ml-2 text-ns-text">{e.summary}</span>
              </div>
            ))}
            {history.map((h, i) => (
              <div key={`h-${i}`} className="rounded border border-ns-border/50 bg-ns-bg px-2 py-1 text-xs text-ns-muted">
                <span className="mr-2 font-mono">{formatDateTime(h.timestamp)}</span>
                {h.kind}
                <span className="ml-2 break-all text-[10px]">{h.payload.slice(0, 140)}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
