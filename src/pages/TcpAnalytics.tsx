import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { takeCaptureHandshakes, takeCaptureMetrics } from '../services/api'
import { useMetricsStore } from '../stores/liveStores'
import { formatMs } from '../utils/format'
import type { HandshakeTiming, TcpMetricEvent } from '../types/diagnostics'

/** TCP Analytics：网络质量面板（明确区分系统级事件与抓包推导指标）。 */
export function TcpAnalyticsPage() {
  const qualityHistory = useMetricsStore((s) => s.qualityHistory)
  const [metrics, setMetrics] = useState<TcpMetricEvent[]>([])
  const [handshakes, setHandshakes] = useState<HandshakeTiming[]>([])
  const [autoPoll, setAutoPoll] = useState(true)
  const timer = useRef<number | null>(null)

  useEffect(() => {
    if (!autoPoll) return
    const poll = () => {
      void takeCaptureMetrics().then((m) => {
        if (m.length) setMetrics((prev) => [...prev, ...m].slice(-500))
      })
      void takeCaptureHandshakes().then((h) => {
        if (h.length) setHandshakes((prev) => [...prev, ...h].slice(-500))
      })
    }
    poll()
    timer.current = window.setInterval(poll, 2000)
    return () => {
      if (timer.current) window.clearInterval(timer.current)
    }
  }, [autoPoll])

  const retrans = metrics.filter((m) => m.kind === 'retransmit')
  const rsts = metrics.filter((m) => m.kind === 'rst')

  const retransByTarget = useMemo(() => {
    const map = new Map<string, number>()
    for (const m of retrans) {
      const key = m.dstIp ? `${m.dstIp}${m.dstPort ? `:${m.dstPort}` : ''}` : '未知'
      map.set(key, (map.get(key) ?? 0) + 1)
    }
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)
  }, [retrans])

  const connTrend = useMemo(
    () =>
      qualityHistory.slice(-120).map((p) => ({
        time: p.timestamp.slice(11, 19),
        established: p.tcpEstablished,
        total: p.tcpTotal,
      })),
    [qualityHistory],
  )

  const handshakeStats = useMemo(() => {
    if (handshakes.length === 0) return null
    const vals = handshakes.map((h) => h.synToSynAckMs).sort((a, b) => a - b)
    const avg = vals.reduce((a, b) => a + b, 0) / vals.length
    const p95 = vals[Math.min(vals.length - 1, Math.floor(vals.length * 0.95))]
    return { count: vals.length, avg, p95, min: vals[0], max: vals[vals.length - 1] }
  }, [handshakes])

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">TCP Analytics</h1>
        <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs text-ns-muted">
          <input type="checkbox" checked={autoPoll} onChange={(e) => setAutoPoll(e.target.checked)} />
          实时轮询抓包指标（Npcap 会话运行时）
        </label>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="rounded-lg border border-ns-border bg-ns-panel p-3">
          <div className="text-xs text-ns-muted">重传事件（抓包推导）</div>
          <div className="mt-1 text-xl font-semibold text-ns-warn">{retrans.length}</div>
        </div>
        <div className="rounded-lg border border-ns-border bg-ns-panel p-3">
          <div className="text-xs text-ns-muted">RST 事件（抓包推导）</div>
          <div className="mt-1 text-xl font-semibold text-ns-error">{rsts.length}</div>
        </div>
        <div className="rounded-lg border border-ns-border bg-ns-panel p-3">
          <div className="text-xs text-ns-muted">建连耗时均值（抓包观测）</div>
          <div className="mt-1 text-xl font-semibold text-ns-accent">
            {handshakeStats ? formatMs(handshakeStats.avg) : '-'}
          </div>
        </div>
        <div className="rounded-lg border border-ns-border bg-ns-panel p-3">
          <div className="text-xs text-ns-muted">活跃 TCP 连接（系统级）</div>
          <div className="mt-1 text-xl font-semibold text-ns-text">
            {qualityHistory.at(-1)?.tcpEstablished ?? '-'}
          </div>
        </div>
      </div>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">
          连接数量趋势（系统级 · 连接表轮询）
        </h2>
        <div className="h-44">
          {connTrend.length > 1 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={connTrend} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 10 }} minTickGap={40} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} width={40} />
                <Tooltip
                  contentStyle={{
                    background: '#111a2c',
                    border: '1px solid #1e293b',
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                />
                <Line type="monotone" dataKey="established" stroke="#22d3ee" dot={false} strokeWidth={1.5} name="已建立" />
                <Line type="monotone" dataKey="total" stroke="#3b82f6" dot={false} strokeWidth={1.5} name="总数" />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-full items-center justify-center text-xs text-ns-muted">
              积累采样中…
            </div>
          )}
        </div>
      </section>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-3 text-sm font-medium text-ns-accent">
            建连耗时（抓包观测 SYN→SYN/ACK）
          </h2>
          {handshakeStats ? (
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-ns-muted">样本数</span>
                <span className="text-ns-text">{handshakeStats.count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-ns-muted">最小 / 均值 / P95 / 最大</span>
                <span className="tabular-nums text-ns-text">
                  {formatMs(handshakeStats.min)} / {formatMs(handshakeStats.avg)} /{' '}
                  {formatMs(handshakeStats.p95)} / {formatMs(handshakeStats.max)}
                </span>
              </div>
              <div className="mt-2 h-32">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={handshakes.slice(-40).map((h) => ({
                      t: h.timestamp.slice(17, 22),
                      ms: Math.round(h.synToSynAckMs * 100) / 100,
                    }))}
                    margin={{ top: 4, right: 8, bottom: 0, left: 0 }}
                  >
                    <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                    <XAxis dataKey="t" tick={{ fill: '#64748b', fontSize: 9 }} />
                    <YAxis tick={{ fill: '#64748b', fontSize: 9 }} width={36} />
                    <Tooltip
                      contentStyle={{
                        background: '#111a2c',
                        border: '1px solid #1e293b',
                        fontSize: 12,
                      }}
                    />
                    <Bar dataKey="ms" fill="#22d3ee" radius={[2, 2, 0, 0]} name="SYN→SYN/ACK (ms)" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          ) : (
            <p className="text-xs text-ns-muted">
              尚无样本。启动 Packet Inspector 抓包后，经过 TLS/HTTPS 握手的连接将产生建连耗时观测。
            </p>
          )}
        </section>

        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-3 text-sm font-medium text-ns-accent">重传目标 Top（抓包推导）</h2>
          {retransByTarget.length > 0 ? (
            <div className="space-y-1">
              {retransByTarget.map(([target, count]) => (
                <div
                  key={target}
                  className="flex items-center justify-between rounded border border-ns-border bg-ns-bg px-2 py-1 text-xs"
                >
                  <span className="font-mono text-ns-text">{target}</span>
                  <span className="text-ns-warn">{count} 次</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-ns-muted">无重传观测（未抓包或链路健康）。</p>
          )}
        </section>
      </div>

      <p className="text-[10px] leading-4 text-ns-muted">
        数据来源标注：本页"抓包推导"指标来自 Npcap 会话（SYN→SYN/ACK 时间差、同 seq
        重复观测等可观测事实）；"系统级"指标来自连接表轮询。RTT 仅在抓包提供
        可靠测量依据时展示，不做猜测性推算。
      </p>
    </div>
  )
}
