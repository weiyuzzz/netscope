import { useState } from 'react'
import { Loader2, MapPin, Play } from 'lucide-react'
import { runPing, runTraceroute } from '../services/api'
import { formatMs } from '../utils/format'
import type { PingResult, RouteProbe } from '../types/diagnostics'

const HOP_STATE_LABEL: Record<string, string> = {
  replied: '应答',
  no_reply: '* 无响应',
  reached: '到达目标',
}

/** Route Explorer：高级路由追踪（ICMP/TCP/UDP）+ Ping + ASN。 */
export function RouteExplorerPage() {
  const [target, setTarget] = useState('1.1.1.1')
  const [protocol, setProtocol] = useState<'icmp' | 'tcp' | 'udp'>('icmp')
  const [maxHops, setMaxHops] = useState(15)
  const [probesPerHop, setProbesPerHop] = useState(3)
  const [probe, setProbe] = useState<RouteProbe | null>(null)
  const [ping, setPing] = useState<PingResult | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const doTrace = async () => {
    setBusy('trace')
    setError(null)
    try {
      setProbe(await runTraceroute(target, protocol, maxHops, probesPerHop, true))
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(null)
    }
  }

  const doPing = async () => {
    setBusy('ping')
    setError(null)
    try {
      setPing(await runPing(target, 4, 2000))
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <h1 className="text-xl font-semibold">Route Explorer</h1>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-xs text-ns-muted">
            目标（IP / 域名）
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="mt-1 block w-52 rounded border border-ns-border bg-ns-bg px-2 py-1.5 font-mono text-xs text-ns-text"
            />
          </label>
          <label className="text-xs text-ns-muted">
            协议
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value as typeof protocol)}
              className="mt-1 block rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            >
              <option value="icmp">ICMP（免管理员）</option>
              <option value="tcp">TCP（需 Npcap + 管理员）</option>
              <option value="udp">UDP（需 Npcap + 管理员）</option>
            </select>
          </label>
          <label className="text-xs text-ns-muted">
            最大跳数
            <input
              type="number"
              min={1}
              max={30}
              value={maxHops}
              onChange={(e) => setMaxHops(Number(e.target.value))}
              className="mt-1 block w-20 rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            />
          </label>
          <label className="text-xs text-ns-muted">
            每跳探测
            <input
              type="number"
              min={1}
              max={5}
              value={probesPerHop}
              onChange={(e) => setProbesPerHop(Number(e.target.value))}
              className="mt-1 block w-20 rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            />
          </label>
          <button
            onClick={() => void doTrace()}
            disabled={busy !== null}
            className="inline-flex items-center gap-1.5 rounded-md border border-ns-accent/50 bg-ns-accent/10 px-3 py-1.5 text-xs text-ns-accent disabled:opacity-50"
          >
            {busy === 'trace' ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <MapPin className="h-3.5 w-3.5" />
            )}
            Traceroute
          </button>
          <button
            onClick={() => void doPing()}
            disabled={busy !== null}
            className="inline-flex items-center gap-1.5 rounded-md border border-ns-border px-3 py-1.5 text-xs text-ns-muted hover:text-ns-text disabled:opacity-50"
          >
            {busy === 'ping' ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            Ping ×4
          </button>
        </div>
        {error && <p className="mt-3 rounded border border-ns-error/40 bg-ns-error/5 p-2 text-xs text-ns-error">{error}</p>}
        <p className="mt-2 text-[10px] text-ns-muted">
          探测结果会以 RouteHop 节点推入 Network Map（边类型 route_probe_path，证据
          probe_observation）。不响应的跳显示为"* 无响应"，不代表该节点故障。
        </p>
      </section>

      {ping && (
        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-2 text-sm font-medium text-ns-accent">
            Ping {ping.targetIp} · 收 {ping.received}/{ping.sent} · 丢包{' '}
            {(ping.lossRate * 100).toFixed(0)}%
            {ping.avgRttMs != null && ` · 均值 ${formatMs(ping.avgRttMs)}`}
          </h2>
          <div className="flex flex-wrap gap-1.5">
            {ping.replies.map((r) => (
              <span
                key={r.seq}
                className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                  r.rttMs != null
                    ? 'bg-ns-ok/10 text-ns-ok'
                    : 'bg-ns-error/10 text-ns-error'
                }`}
              >
                #{r.seq + 1} {r.rttMs != null ? formatMs(r.rttMs) : '超时'}
              </span>
            ))}
          </div>
        </section>
      )}

      {probe && (
        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-3 text-sm font-medium text-ns-accent">
            Traceroute → {probe.target} ({probe.resolvedIp ?? '未解析'}) ·{' '}
            {probe.protocol.toUpperCase()} · {probe.hops.length} 跳
          </h2>
          <table className="w-full text-left text-xs">
            <thead className="text-ns-muted">
              <tr>
                <th className="pb-1.5 font-medium">TTL</th>
                <th className="pb-1.5 font-medium">IP</th>
                <th className="pb-1.5 font-medium">RTT</th>
                <th className="pb-1.5 font-medium">丢包</th>
                <th className="pb-1.5 font-medium">ASN</th>
                <th className="pb-1.5 font-medium">状态</th>
              </tr>
            </thead>
            <tbody>
              {probe.hops.map((h) => (
                <tr key={h.ttl} className="border-t border-ns-border/60">
                  <td className="py-1.5 font-mono text-ns-muted">{h.ttl}</td>
                  <td className="py-1.5 font-mono text-ns-text">{h.ip ?? '*'}</td>
                  <td className="py-1.5 font-mono text-ns-muted">
                    {h.rttMs.length > 0
                      ? h.rttMs.map((r) => formatMs(r)).join(' / ')
                      : '-'}
                  </td>
                  <td className="py-1.5 text-ns-muted">
                    {h.probesSent - h.rttMs.length}/{h.probesSent}
                  </td>
                  <td className="py-1.5 text-ns-muted">{h.asn ?? '-'}</td>
                  <td className="py-1.5">
                    <span
                      className={`text-[10px] ${
                        h.state === 'reached'
                          ? 'text-ns-ok'
                          : h.state === 'replied'
                            ? 'text-ns-accent'
                            : 'text-ns-muted'
                      }`}
                    >
                      {HOP_STATE_LABEL[h.state]}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  )
}
