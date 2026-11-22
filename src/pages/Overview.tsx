import { useMemo } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { AlertTriangle, ArrowDown, ArrowUp, Globe, ShieldCheck, Wifi } from 'lucide-react'
import { useMetricsStore } from '../stores/liveStores'
import { useAppInfo } from '../hooks/useAppInfo'
import { formatBps, formatTime } from '../utils/format'
import type { NetworkQualityPoint } from '../types/network'

function MetricCard({
  label,
  value,
  sub,
  icon: Icon,
  accent,
}: {
  label: string
  value: string
  sub?: string
  icon: typeof Globe
  accent: string
}) {
  return (
    <div className="rounded-lg border border-ns-border bg-ns-panel p-3">
      <div className="flex items-center gap-2 text-xs text-ns-muted">
        <Icon className={`h-4 w-4 ${accent}`} />
        {label}
      </div>
      <div className="mt-1.5 text-xl font-semibold tabular-nums text-ns-text">{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-ns-muted">{sub}</div>}
    </div>
  )
}

/** Overview：实时网络运行状态（全部来自后台采集循环）。 */
export function OverviewPage() {
  const { info } = useAppInfo()
  const rates = useMetricsStore((s) => s.interfaceRates)
  const history = useMetricsStore((s) => s.qualityHistory)
  const proxyServers = useMetricsStore((s) => s.proxyServers)
  const vpnInterfaces = useMetricsStore((s) => s.vpnInterfaces)
  const connectionCount = useMetricsStore((s) => s.connectionCount)
  const activeProcesses = useMetricsStore((s) => s.activeProcesses)
  const errors = useMetricsStore((s) => s.collectorErrors)

  const { rx, tx } = useMemo(
    () =>
      rates.reduce(
        (acc, r) => ({ rx: acc.rx + r.rxBps, tx: acc.tx + r.txBps }),
        { rx: 0, tx: 0 },
      ),
    [rates],
  )

  const chartData = useMemo(
    () =>
      history.map((p: NetworkQualityPoint) => ({
        time: formatTime(p.timestamp),
        下行: Math.round(p.rxBps / 1024),
        上行: Math.round(p.txBps / 1024),
      })),
    [history],
  )

  const activeVpn = vpnInterfaces.filter((v) => v.active)
  const localProxies = proxyServers.filter(
    (p) => p.mechanism === 'local_listener' || p.mechanism === 'win_inet',
  )

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      {errors.length > 0 && (
        <div className="flex items-center gap-2 rounded-lg border border-ns-warn/40 bg-ns-warn/5 p-2.5 text-xs text-ns-warn">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          采集异常：{errors.join('；')}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          label="下载速率"
          value={formatBps(rx)}
          sub="全部网卡合计"
          icon={ArrowDown}
          accent="text-ns-ok"
        />
        <MetricCard
          label="上传速率"
          value={formatBps(tx)}
          sub="全部网卡合计"
          icon={ArrowUp}
          accent="text-ns-accent"
        />
        <MetricCard
          label="连接数"
          value={String(connectionCount)}
          sub={`TCP + UDP 端点`}
          icon={Wifi}
          accent="text-ns-blue"
        />
        <MetricCard
          label="活跃进程"
          value={String(activeProcesses)}
          sub="有网络活动的进程"
          icon={Globe}
          accent="text-ns-purple"
        />
      </div>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">流量趋势（KB/s）</h2>
        <div className="h-44">
          {chartData.length > 1 ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 10 }} minTickGap={40} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} width={44} />
                <Tooltip
                  contentStyle={{
                    background: '#111a2c',
                    border: '1px solid #1e293b',
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                />
                <Area type="monotone" dataKey="下行" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.12} strokeWidth={1.5} />
                <Area type="monotone" dataKey="上行" stroke="#a78bfa" fill="#a78bfa" fillOpacity={0.12} strokeWidth={1.5} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-full items-center justify-center text-xs text-ns-muted">
              正在积累采样点…（约 10 秒后出现曲线）
            </div>
          )}
        </div>
      </section>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-3 text-sm font-medium text-ns-accent">网卡与实时速率</h2>
          {rates.length === 0 ? (
            <p className="text-xs text-ns-muted">等待计数器差分（约 3 秒）…</p>
          ) : (
            <table className="w-full text-xs">
              <thead className="text-ns-muted">
                <tr>
                  <th className="pb-1.5 text-left font-medium">网卡</th>
                  <th className="pb-1.5 text-right font-medium">下行</th>
                  <th className="pb-1.5 text-right font-medium">上行</th>
                </tr>
              </thead>
              <tbody>
                {rates
                  .filter((r) => r.rxBps > 1 || r.txBps > 1)
                  .map((r) => (
                    <tr key={r.ifIndex} className="border-t border-ns-border/60">
                      <td className="py-1.5 text-ns-text">
                        {r.friendlyName}
                        {r.operationalStatus && (
                          <span className="ml-1.5 text-[10px] text-ns-muted">{r.operationalStatus}</span>
                        )}
                      </td>
                      <td className="py-1.5 text-right tabular-nums text-ns-ok">{formatBps(r.rxBps)}</td>
                      <td className="py-1.5 text-right tabular-nums text-ns-accent">{formatBps(r.txBps)}</td>
                    </tr>
                  ))}
                {rates.every((r) => r.rxBps <= 1 && r.txBps <= 1) && (
                  <tr>
                    <td colSpan={3} className="py-2 text-ns-muted">
                      当前无显著流量
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </section>

        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-3 flex items-center gap-1.5 text-sm font-medium text-ns-accent">
            <ShieldCheck className="h-4 w-4 text-ns-purple" /> 代理 / VPN 状态
          </h2>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between">
              <span className="text-ns-muted">代理服务</span>
              <span className="text-ns-text">{localProxies.length} 个</span>
            </div>
            {localProxies.slice(0, 4).map((p) => (
              <div key={p.id} className="rounded border border-ns-border bg-ns-bg px-2 py-1">
                <span className="text-ns-text">
                  {p.host}:{p.port}
                </span>
                <span className="ml-2 text-[10px] text-ns-muted">{p.mechanism}</span>
                {p.processName && <span className="ml-2 text-[10px] text-ns-muted">{p.processName}</span>}
              </div>
            ))}
            <div className="flex justify-between pt-1">
              <span className="text-ns-muted">VPN / 虚拟网卡</span>
              <span className="text-ns-text">{activeVpn.length} 个</span>
            </div>
            {activeVpn.slice(0, 4).map((v) => (
              <div key={v.ifIndex} className="rounded border border-ns-border bg-ns-bg px-2 py-1">
                <span className="text-ns-text">{v.friendlyName}</span>
                <span className="ml-2 text-[10px] text-ns-muted">{v.kind}</span>
                {v.isDefaultRouteOwner && (
                  <span className="ml-1.5 rounded bg-ns-purple/15 px-1 text-[10px] text-ns-purple">
                    默认路由出口
                  </span>
                )}
              </div>
            ))}
            <p className="pt-1 text-[10px] text-ns-muted">
              详细分析与出口 IP 探测见 Proxy Analysis 页面。
            </p>
          </div>
        </section>
      </div>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-2 text-sm font-medium text-ns-accent">运行环境</h2>
        <p className="text-xs text-ns-muted">
          {info
            ? `NetScope v${info.version} · ${info.os} (${info.arch}) · 主机 ${info.hostname}`
            : '加载中…'}
        </p>
      </section>
    </div>
  )
}
