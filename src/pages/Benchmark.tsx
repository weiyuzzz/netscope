import { useCallback, useEffect, useState } from 'react'
import { Loader2, Play } from 'lucide-react'
import { compareBenchmarks, getBenchmarks, runBenchmark } from '../services/api'
import { formatBps, formatDateTime, formatMs } from '../utils/format'
import type { BenchmarkResultR3 } from '../types/diagnostics'

const KIND_LABEL: Record<string, string> = {
  ping: '多目标 Ping',
  dns: 'DNS Benchmark',
  tcp_connect: 'TCP 连接基准',
  http: 'HTTP 请求耗时',
  download: '下载速度（用户指定目标）',
  upload: '上传速度（用户指定目标）',
}

function fmtMetrics(kind: string, m: Record<string, unknown>): string {
  const num = (k: string) => (typeof m[k] === 'number' ? (m[k] as number) : null)
  switch (kind) {
    case 'ping': {
      const avg = num('avgMs')
      const loss = num('lossRate')
      return `丢包 ${(loss ?? 0) * 100}%${avg != null ? ` · 均值 ${formatMs(avg)}` : ''} (${m.received}/${m.sent})`
    }
    case 'dns': {
      const avg = num('avgMs')
      const rate = num('successRate')
      return `成功率 ${(rate ?? 0) * 100}%${avg != null ? ` · 均值 ${formatMs(avg)}` : ''} (${m.success}/${m.total})`
    }
    case 'tcp_connect': {
      const avg = num('avgMs')
      return `成功率 ${(num('successRate') ?? 0) * 100}%${avg != null ? ` · 均值 ${formatMs(avg)}` : ''}`
    }
    case 'http':
      return `HTTP ${m.httpCode} · 总耗时 ${formatMs(num('totalMs') ?? 0)} · 首字节 ${formatMs(num('ttfbMs') ?? 0)}`
    case 'download':
      return `${formatBps(num('bytesPerSec') ?? 0)} · ${(num('bytes') ?? 0) / 1024 / 1024}MB`
    case 'upload':
      return `${formatBps(num('bytesPerSec') ?? 0)} · ${(num('bytes') ?? 0) / 1024 / 1024}MB`
    default:
      return JSON.stringify(m).slice(0, 60)
  }
}

/** Benchmark：网络质量基准测试（多目标 / DNS / TCP / HTTP / 下载 / 上传）。 */
export function BenchmarkPage() {
  const [kind, setKind] = useState('ping')
  const [targets, setTargets] = useState('1.1.1.1\n8.8.8.8\n223.5.5.5')
  const [count, setCount] = useState(4)
  const [maxBytes, setMaxBytes] = useState(50)
  const [maxSeconds, setMaxSeconds] = useState(15)
  const [results, setResults] = useState<BenchmarkResultR3[]>([])
  const [history, setHistory] = useState<BenchmarkResultR3[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [compareResult, setCompareResult] = useState<Record<string, unknown> | null>(null)
  const [compareTarget, setCompareTarget] = useState('')

  const refresh = useCallback(async () => {
    setHistory(await getBenchmarks(30).catch(() => []))
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const run = async () => {
    setBusy(true)
    setError(null)
    try {
      const list = targets.split('\n').map((t) => t.trim()).filter(Boolean)
      if (list.length === 0) {
        setError('请至少输入一个测试目标')
        return
      }
      const r = await runBenchmark(kind, list, {
        count,
        maxBytes: maxBytes * 1024 * 1024,
        maxSeconds,
      })
      setResults(r)
      void refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const needsTargetsPerLine = kind === 'ping' || kind === 'dns' || kind === 'tcp_connect' || kind === 'http'
  const isTransfer = kind === 'download' || kind === 'upload'

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <h1 className="text-xl font-semibold">Network Quality Benchmark</h1>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-xs text-ns-muted">
            测试类型
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value)}
              className="mt-1 block rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            >
              {Object.entries(KIND_LABEL).map(([v, label]) => (
                <option key={v} value={v}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          {!isTransfer && (
            <label className="text-xs text-ns-muted">
              每目标次数
              <input
                type="number"
                min={1}
                max={20}
                value={count}
                onChange={(e) => setCount(Number(e.target.value))}
                className="mt-1 block w-20 rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
              />
            </label>
          )}
          {isTransfer && (
            <>
              <label className="text-xs text-ns-muted">
                流量上限 (MB)
                <input
                  type="number"
                  min={1}
                  max={200}
                  value={maxBytes}
                  onChange={(e) => setMaxBytes(Number(e.target.value))}
                  className="mt-1 block w-24 rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
                />
              </label>
              <label className="text-xs text-ns-muted">
                时间上限 (秒)
                <input
                  type="number"
                  min={5}
                  max={300}
                  value={maxSeconds}
                  onChange={(e) => setMaxSeconds(Number(e.target.value))}
                  className="mt-1 block w-24 rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
                />
              </label>
            </>
          )}
          <button
            onClick={() => void run()}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-md border border-ns-accent/50 bg-ns-accent/10 px-3 py-1.5 text-xs text-ns-accent disabled:opacity-50"
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            开始测试
          </button>
        </div>
        <label className="mt-3 block text-xs text-ns-muted">
          测试目标（每行一个{needsTargetsPerLine ? '：IP / 域名 / URL' : isTransfer ? '：URL，必须为你明确选择的目标' : ''}）
          <textarea
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            rows={4}
            className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 font-mono text-xs text-ns-text"
          />
        </label>
        {isTransfer && (
          <p className="text-[10px] text-ns-muted">
            下载/上传测试严格受流量与时间上限约束；上传为 POST 明文传输到你所填 URL，请仅使用你有权使用的服务。
          </p>
        )}
        {error && <p className="mt-2 text-xs text-ns-error">{error}</p>}
      </section>

      {results.length > 0 && (
        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-3 text-sm font-medium text-ns-accent">本次结果</h2>
          <table className="w-full text-left text-xs">
            <thead className="text-ns-muted">
              <tr>
                <th className="pb-1.5 font-medium">目标</th>
                <th className="pb-1.5 font-medium">结果</th>
                <th className="pb-1.5 font-medium">接口/代理</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r) => (
                <tr key={r.id} className="border-t border-ns-border/60">
                  <td className="py-1.5 font-mono text-ns-text">{r.target}</td>
                  <td className="py-1.5 text-ns-muted">
                    {r.error ? <span className="text-ns-error">{r.error}</span> : fmtMetrics(r.kind, r.metrics)}
                  </td>
                  <td className="py-1.5 text-ns-muted">
                    {r.interface ?? '-'}
                    {r.proxyMode && ` · ${r.proxyMode}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">两个网络环境对比（同一目标的历史测试）</h2>
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-xs text-ns-muted">
            目标（与历史记录匹配）
            <input
              value={compareTarget}
              onChange={(e) => setCompareTarget(e.target.value)}
              placeholder="例如 1.1.1.1 或 https://..."
              className="mt-1 block w-64 rounded border border-ns-border bg-ns-bg px-2 py-1.5 font-mono text-xs text-ns-text"
            />
          </label>
          <button
            onClick={() => {
              setBusy(true)
              setError(null)
              compareBenchmarks(kind, compareTarget.trim())
                .then((r) => setCompareResult(r))
                .catch((e) => setError(String(e)))
                .finally(() => setBusy(false))
            }}
            disabled={busy || !compareTarget.trim()}
            className="inline-flex items-center gap-1.5 rounded-md border border-ns-purple/50 bg-ns-purple/10 px-3 py-1.5 text-xs text-ns-purple disabled:opacity-50"
          >
            对比
          </button>
        </div>
        {compareResult && (
          <div className="mt-3 rounded-lg border border-ns-border bg-ns-bg p-3 text-xs">
            <div className="text-ns-text">{String(compareResult.summary ?? '')}</div>
            <div className="mt-1 text-[11px] text-ns-muted">
              较早：{String((compareResult.older as Record<string, unknown>)?.at ?? '')} · 较近：
              {String((compareResult.newer as Record<string, unknown>)?.at ?? '')}
            </div>
          </div>
        )}
        <p className="mt-2 text-[10px] text-ns-muted">
          用于对比不同网络环境（如切换 VPN 节点前后、不同网卡下）对同一目标的测试结果。
        </p>
      </section>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">历史测试</h2>
        {history.length === 0 ? (
          <p className="text-xs text-ns-muted">暂无历史记录。</p>
        ) : (
          <div className="max-h-72 space-y-1 overflow-auto">
            {history.map((r) => (
              <div key={r.id} className="flex items-baseline gap-2 rounded border border-ns-border/60 bg-ns-bg px-2 py-1 text-[11px]">
                <span className="font-mono text-ns-muted">{formatDateTime(r.startedAt)}</span>
                <span className="text-ns-accent">{KIND_LABEL[r.kind] ?? r.kind}</span>
                <span className="font-mono text-ns-text">{r.target}</span>
                <span className="text-ns-muted">{r.error ?? fmtMetrics(r.kind, r.metrics)}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
