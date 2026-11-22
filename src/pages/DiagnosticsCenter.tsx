import { useCallback, useEffect, useState } from 'react'
import { FileDown, FileJson, Loader2, Play, RefreshCw } from 'lucide-react'
import {
  exportReport,
  getFindings,
  getRuleRegistry,
  packageDiagnostics,
  runDiagnostics,
  runRca,
  setRuleEnabled,
} from '../services/api'
import { confidenceLabel, formatDateTime } from '../utils/format'
import { useAppStore } from '../stores/appStore'
import type {
  DiagnosticFinding,
  DiagnosticRuleMeta,
  RcaReport,
} from '../types/diagnostics'

/** Diagnostics Center：规则诊断 + 根因分析 + 报告导出。 */
export function DiagnosticsCenterPage() {
  const setCurrentPage = useAppStore((s) => s.setCurrentPage)
  const setFocusTime = useAppStore((s) => s.setFocusTime)
  const [findings, setFindings] = useState<DiagnosticFinding[]>([])
  const [registry, setRegistry] = useState<DiagnosticRuleMeta[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [subject, setSubject] = useState('google.com')
  const [rca, setRca] = useState<RcaReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [exportInfo, setExportInfo] = useState<string | null>(null)
  const [mask, setMask] = useState({ localIps: true, publicIps: false, hostnames: false, domains: false })

  const refresh = useCallback(async () => {
    setFindings(await getFindings(50).catch(() => []))
    setRegistry(await getRuleRegistry().catch(() => []))
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const runDiag = async () => {
    setBusy('diag')
    setError(null)
    try {
      const f = await runDiagnostics(15)
      await refresh()
      if (f.length === 0) setExportInfo('最近 15 分钟未触发任何诊断规则。')
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(null)
    }
  }

  const doRca = async () => {
    setBusy('rca')
    setError(null)
    try {
      setRca(await runRca(subject.trim(), 15))
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(null)
    }
  }

  const doExport = async (kind: string) => {
    setBusy(kind)
    try {
      const r = await exportReport(kind, 30, mask)
      setExportInfo(`${kind.toUpperCase()} 已导出：${r.path}`)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(null)
    }
  }

  const toggleRule = async (ruleId: string, enabled: boolean) => {
    await setRuleEnabled(ruleId, enabled).catch(() => {})
    setRegistry((reg) => reg.map((r) => (r.ruleId === ruleId ? { ...r, enabled } : r)))
  }

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Diagnostics Center</h1>
        <button
          onClick={() => void runDiag()}
          disabled={busy === 'diag'}
          className="inline-flex items-center gap-1.5 rounded-md border border-ns-accent/50 bg-ns-accent/10 px-3 py-1.5 text-xs text-ns-accent disabled:opacity-50"
        >
          {busy === 'diag' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          立即诊断（最近 15 分钟）
        </button>
      </div>
      {error && <p className="rounded border border-ns-error/40 bg-ns-error/5 p-2 text-xs text-ns-error">{error}</p>}
      {exportInfo && <p className="rounded border border-ns-ok/40 bg-ns-ok/5 p-2 text-xs text-ns-ok">{exportInfo}</p>}

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">诊断结论（{findings.length}）</h2>
        {findings.length === 0 ? (
          <p className="text-xs text-ns-muted">
            暂无诊断结论。异常发生时规则引擎自动产生结论，也可点击"立即诊断"。
          </p>
        ) : (
          <div className="space-y-2">
            {findings.map((f, i) => {
              const conf = confidenceLabel(f.confidence)
              return (
                <div key={i}
                  className="cursor-pointer rounded-lg border border-ns-border bg-ns-bg p-3 text-xs hover:border-ns-accent/60"
                  title="点击跳转到该时刻的 History 回放"
                  onClick={() => {
                    setFocusTime(f.detectedAt)
                    setCurrentPage('history')
                  }}>
                  <div className="flex items-center gap-2">
                    <span
                      className={
                        f.severity === 'critical'
                          ? 'text-ns-error'
                          : f.severity === 'warning'
                            ? 'text-ns-warn'
                            : 'text-ns-muted'
                      }
                    >
                      [{f.severity}]
                    </span>
                    <span className="font-medium text-ns-text">{f.title}</span>
                    <span className={`ml-auto ${conf.cls}`}>置信度 {conf.label}</span>
                  </div>
                  <div className="mt-1.5 space-y-0.5 text-[11px] text-ns-muted">
                    <div>检测时间：{formatDateTime(f.detectedAt)} · 规则 {f.ruleId}</div>
                    {f.evidence.length > 0 && (
                      <div>
                        证据：
                        {f.evidence.map((e, j) => (
                          <span key={j} className="mr-1">
                            （{formatDateTime(e.timestamp)}，{e.source}）{e.description}
                          </span>
                        ))}
                      </div>
                    )}
                    <div>可能原因：{f.possibleCauses.join('；')}</div>
                    <div>验证建议：{f.verification.join('；')}</div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </section>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">根因关联分析（RCA）</h2>
        <div className="flex items-end gap-3">
          <label className="text-xs text-ns-muted">
            分析对象（域名 / 进程 / IP）
            <input
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              className="mt-1 block w-60 rounded border border-ns-border bg-ns-bg px-2 py-1.5 font-mono text-xs text-ns-text"
            />
          </label>
          <button
            onClick={() => void doRca()}
            disabled={busy === 'rca' || !subject.trim()}
            className="inline-flex items-center gap-1.5 rounded-md border border-ns-purple/50 bg-ns-purple/10 px-3 py-1.5 text-xs text-ns-purple disabled:opacity-50"
          >
            {busy === 'rca' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            分析最近 15 分钟
          </button>
        </div>
        {rca && (
          <div className="mt-3 rounded-lg border border-ns-border bg-ns-bg p-3 text-xs">
            <div className="text-ns-text">{rca.symptom}</div>
            <div className="mt-2 text-[11px] text-ns-muted">观察证据：</div>
            {rca.observations.map((o, i) => (
              <div key={i} className="text-[11px] text-ns-muted">
                · （{formatDateTime(o.timestamp)}，{o.source}）{o.description}
              </div>
            ))}
            <div className="mt-2 text-[11px] text-ns-muted">可能原因：</div>
            {rca.causes.map((c, i) => {
              const conf = confidenceLabel(c.confidence)
              return (
                <div key={i} className="text-[11px]">
                  <span className={`mr-1 ${conf.cls}`}>[{conf.label}]</span>
                  <span className="text-ns-text">{c.description}</span>
                  <span className="ml-1 text-ns-muted">（{c.evidence.length} 条证据）</span>
                </div>
              );
            })}
            <div className="mt-2 text-[11px] text-ns-muted">建议：{rca.suggestions.join('；')}</div>
          </div>
        )}
      </section>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">报告导出</h2>
        <div className="mb-3 flex flex-wrap gap-3 text-xs text-ns-muted">
          <span>脱敏：</span>
          {(
            [
              ['localIps', '本地 IP'],
              ['publicIps', '公网 IP'],
              ['hostnames', '主机名'],
              ['domains', '域名'],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="inline-flex items-center gap-1">
              <input
                type="checkbox"
                checked={mask[key]}
                onChange={(e) => setMask((m) => ({ ...m, [key]: e.target.checked }))}
              />
              {label}
            </label>
          ))}
        </div>
        <div className="flex gap-2">
          <button onClick={() => void doExport('html')} disabled={busy !== null} className="inline-flex items-center gap-1.5 rounded-md border border-ns-border px-3 py-1.5 text-xs text-ns-muted hover:text-ns-text disabled:opacity-50">
            <FileDown className="h-3.5 w-3.5" /> HTML
          </button>
          <button onClick={() => void doExport('json')} disabled={busy !== null} className="inline-flex items-center gap-1.5 rounded-md border border-ns-border px-3 py-1.5 text-xs text-ns-muted hover:text-ns-text disabled:opacity-50">
            <FileJson className="h-3.5 w-3.5" /> JSON
          </button>
          <button onClick={() => void doExport('pdf')} disabled={busy !== null} className="inline-flex items-center gap-1.5 rounded-md border border-ns-border px-3 py-1.5 text-xs text-ns-muted hover:text-ns-text disabled:opacity-50">
            <FileDown className="h-3.5 w-3.5" /> PDF（经系统 Edge）
          </button>
          <button onClick={() => void packageDiagnostics().then((r) => setExportInfo(`打包完成：${r.kind}`)).catch((e) => setError(String(e)))} disabled={busy !== null} className="inline-flex items-center gap-1.5 rounded-md border border-ns-accent/50 bg-ns-accent/10 px-3 py-1.5 text-xs text-ns-accent disabled:opacity-50">
            一键打包（报告 + 数据库备份）
          </button>
        </div>
      </section>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">诊断规则（{registry.length}）</h2>
        <table className="w-full text-left text-xs">
          <thead className="text-ns-muted">
            <tr>
              <th className="pb-1.5 font-medium">规则</th>
              <th className="pb-1.5 font-medium">类别</th>
              <th className="pb-1.5 font-medium">严重度</th>
              <th className="pb-1.5 font-medium">说明</th>
              <th className="pb-1.5 font-medium">启用</th>
            </tr>
          </thead>
          <tbody>
            {registry.map((r) => (
              <tr key={r.ruleId} className="border-t border-ns-border/60">
                <td className="py-1.5 font-mono text-[11px] text-ns-text">{r.ruleId}</td>
                <td className="py-1.5 text-ns-muted">{r.category}</td>
                <td className="py-1.5">
                  <span className={r.severity === 'critical' ? 'text-ns-error' : r.severity === 'warning' ? 'text-ns-warn' : 'text-ns-muted'}>
                    {r.severity}
                  </span>
                </td>
                <td className="py-1.5 text-ns-muted">{r.description}</td>
                <td className="py-1.5">
                  <input type="checkbox" checked={r.enabled} onChange={(e) => void toggleRule(r.ruleId, e.target.checked)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}
