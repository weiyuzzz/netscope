import { useCallback, useEffect, useRef, useState } from 'react'
import { CircleStop, Play, Radio } from 'lucide-react'
import {
  getSessionEvents,
  listSessions,
  startRecording,
  stopRecording,
} from '../services/api'
import { formatDateTime } from '../utils/format'
import type { RecordingSession, SessionEvent } from '../types/diagnostics'

const KIND_LABEL: Record<string, string> = {
  conn_opened: '连接打开',
  conn_updated: '连接更新',
  conn_closed: '连接关闭',
  dns_new: 'DNS 解析',
  proxy_detected: '代理出现',
  proxy_changed: '代理变化',
  proxy_removed: '代理移除',
  interface_changed: '网卡变化',
  ip_changed: 'IP 变化',
  speed_dropped: '速率下降',
  route_changed: '路由变化',
  quality_sample: '质量采样',
}

const TEST_KINDS = [
  ['browser', '浏览器访问测试'],
  ['vpn', 'VPN 节点测试'],
  ['download', '下载测试'],
  ['network_switch', '网络切换测试'],
  ['custom', '自定义测试'],
] as const

/** Session Recorder：录制一次网络测试任务并自动生成报告。 */
export function SessionRecorderPage() {
  const [name, setName] = useState('')
  const [scopeMode, setScopeMode] = useState<'all' | 'process' | 'domain'>('all')
  const [scopeValue, setScopeValue] = useState('')
  const [testKind, setTestKind] = useState<string>('browser')
  const [recording, setRecording] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sessions, setSessions] = useState<RecordingSession[]>([])
  const [detail, setDetail] = useState<{ session: RecordingSession; events: SessionEvent[] } | null>(null)
  const [report, setReport] = useState<Record<string, unknown> | null>(null)
  const timer = useRef<number | null>(null)

  const refresh = useCallback(async () => {
    setSessions(await listSessions(30).catch(() => []))
    // 录制中状态恢复（重启后）
    try {
      const s = await import('../services/api').then((m) => m.getCollectionSettings())
      void s
    } catch {
      /* 忽略 */
    }
  }, [])

  useEffect(() => {
    void refresh()
    timer.current = window.setInterval(() => void refresh(), 5000)
    return () => {
      if (timer.current) window.clearInterval(timer.current)
    }
  }, [refresh])

  const start = async () => {
    setBusy(true)
    setError(null)
    try {
      await startRecording(
        name.trim() || `网络测试 ${new Date().toLocaleTimeString('zh-CN')}`,
        scopeMode,
        scopeValue.trim() || null,
        testKind,
      )
      setRecording(true)
      setReport(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const stop = async () => {
    setBusy(true)
    setError(null)
    try {
      const r = await stopRecording()
      setRecording(false)
      setReport(r)
      void refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const openDetail = async (s: RecordingSession) => {
    const events = await getSessionEvents(s.id, 500).catch(() => [])
    setDetail({ session: s, events })
  }

  const byKind = (report?.byKind ?? {}) as Record<string, number>
  const findings = (report?.findings ?? []) as import('../types/diagnostics').DiagnosticFinding[]

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <h1 className="text-xl font-semibold">Session Recorder</h1>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 flex items-center gap-1.5 text-sm font-medium text-ns-accent">
          <Radio className="h-4 w-4" /> 新建录制任务
        </h2>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <label className="text-xs text-ns-muted">
            测试名称
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={recording}
              placeholder="例如：Google 访问测试"
              className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            />
          </label>
          <label className="text-xs text-ns-muted">
            任务类型
            <select
              value={testKind}
              onChange={(e) => setTestKind(e.target.value)}
              disabled={recording}
              className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            >
              {TEST_KINDS.map(([v, label]) => (
                <option key={v} value={v}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-ns-muted">
            监控范围
            <select
              value={scopeMode}
              onChange={(e) => setScopeMode(e.target.value as typeof scopeMode)}
              disabled={recording}
              className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            >
              <option value="all">全部网络活动</option>
              <option value="process">指定进程</option>
              <option value="domain">指定域名</option>
            </select>
          </label>
          {scopeMode !== 'all' && (
            <label className="text-xs text-ns-muted">
              {scopeMode === 'process' ? '进程名' : '域名'}
              <input
                value={scopeValue}
                onChange={(e) => setScopeValue(e.target.value)}
                disabled={recording}
                placeholder={scopeMode === 'process' ? 'chrome.exe' : 'google.com'}
                className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 font-mono text-xs text-ns-text"
              />
            </label>
          )}
        </div>
        <div className="mt-3 flex items-center gap-3">
          {!recording ? (
            <button
              onClick={() => void start()}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-md border border-ns-ok/50 bg-ns-ok/10 px-3 py-1.5 text-xs text-ns-ok disabled:opacity-40"
            >
              <Play className="h-3.5 w-3.5" /> 开始录制
            </button>
          ) : (
            <button
              onClick={() => void stop()}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-md border border-ns-error/50 bg-ns-error/10 px-3 py-1.5 text-xs text-ns-error"
            >
              <CircleStop className="h-3.5 w-3.5" /> 停止录制并生成报告
            </button>
          )}
          {recording && (
            <span className="inline-flex items-center gap-1.5 text-xs text-ns-error">
              <span className="h-2 w-2 animate-pulse rounded-full bg-ns-error" />
              录制中…
            </span>
          )}
        </div>
        {error && <p className="mt-2 text-xs text-ns-error">{error}</p>}
      </section>

      {report && (
        <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
          <h2 className="mb-3 text-sm font-medium text-ns-accent">录制报告</h2>
          <div className="mb-2 text-xs text-ns-muted">
            共录制 {String(report.eventCount ?? 0)} 条事件
            {Object.keys(byKind).length > 0 && (
              <span className="ml-2">
                （{Object.entries(byKind).map(([k, v]) => `${KIND_LABEL[k] ?? k} ${v}`).join('，')}）
              </span>
            )}
          </div>
          {findings.length > 0 ? (
            <div className="space-y-2">
              {findings.map((f, i) => (
                <div key={i} className="rounded border border-ns-border bg-ns-bg p-2 text-xs">
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
                  </span>{' '}
                  <span className="text-ns-text">{f.title}</span>
                  <div className="mt-1 text-[11px] text-ns-muted">证据：{f.evidence.map((e) => e.description).join('；')}</div>
                  <div className="text-[11px] text-ns-muted">建议：{f.verification.join('；')}</div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-ns-ok">本次录制未触发诊断规则（网络行为正常或证据不足）。</p>
          )}
        </section>
      )}

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">历史录制任务</h2>
        {sessions.length === 0 ? (
          <p className="text-xs text-ns-muted">暂无录制任务。</p>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-ns-muted">
              <tr>
                <th className="pb-1.5 font-medium">名称</th>
                <th className="pb-1.5 font-medium">类型</th>
                <th className="pb-1.5 font-medium">开始时间</th>
                <th className="pb-1.5 font-medium">事件数</th>
                <th className="pb-1.5 font-medium">状态</th>
                <th className="pb-1.5 font-medium">明细</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id} className="border-t border-ns-border/60">
                  <td className="py-1.5 text-ns-text">{s.name}</td>
                  <td className="py-1.5 text-ns-muted">
                    {TEST_KINDS.find(([v]) => v === s.testKind)?.[1] ?? s.testKind}
                  </td>
                  <td className="py-1.5 text-ns-muted">{formatDateTime(s.startedAt)}</td>
                  <td className="py-1.5 text-ns-muted">{s.eventCount}</td>
                  <td className="py-1.5">
                    <span className={s.status === 'recording' ? 'text-ns-error' : 'text-ns-ok'}>
                      {s.status}
                    </span>
                  </td>
                  <td className="py-1.5">
                    <button className="text-ns-accent hover:underline" onClick={() => void openDetail(s)}>
                      查看
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {detail && (
          <div className="mt-3 max-h-72 overflow-auto rounded border border-ns-border bg-ns-bg p-2">
            {detail.events.map((e, i) => (
              <div key={i} className="py-0.5 text-[11px]">
                <span className="mr-2 font-mono text-ns-muted">{formatDateTime(e.timestamp)}</span>
                <span className="mr-2 rounded bg-ns-panel px-1 text-[10px] text-ns-accent">
                  {KIND_LABEL[e.kind] ?? e.kind}
                </span>
                <span className="text-ns-text">{e.summary}</span>
              </div>
            ))}
            {detail.events.length === 0 && <p className="text-xs text-ns-muted">无事件。</p>}
          </div>
        )}
      </section>
    </div>
  )
}
