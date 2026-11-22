import { useCallback, useEffect, useRef, useState } from 'react'
import { Loader2, Send, Sparkles } from 'lucide-react'
import { aiAsk, getAiConfig, getAiHistory, setAiConfig } from '../services/api'
import { formatDateTime } from '../utils/format'
import type { AiConfigPayload, AiConversation } from '../types/diagnostics'

/** AI Network Assistant：仅基于已采集的结构化证据回答（证据不足时如实说明）。 */
export function AiAssistantPage() {
  const [history, setHistory] = useState<AiConversation[]>([])
  const [question, setQuestion] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [config, setConfig] = useState<AiConfigPayload | null>(null)
  const [showConfig, setShowConfig] = useState(false)
  const [cfgKind, setCfgKind] = useState('offline')
  const [cfgUrl, setCfgUrl] = useState('')
  const [cfgModel, setCfgModel] = useState('')
  const [cfgKey, setCfgKey] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  const refresh = useCallback(async () => {
    setHistory(await getAiHistory(30).catch(() => []))
    const c = await getAiConfig().catch(() => null)
    if (c) {
      setConfig(c)
      setCfgKind(c.kind)
      setCfgUrl(c.baseUrl ?? '')
      setCfgModel(c.model ?? '')
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const ask = async () => {
    const q = question.trim()
    if (!q || busy) return
    setBusy(true)
    setError(null)
    try {
      const conv = await aiAsk(q)
      setHistory((h) => [conv, ...h])
      setQuestion('')
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const saveConfig = async () => {
    setBusy(true)
    try {
      await setAiConfig(cfgKind, cfgUrl.trim() || null, cfgKey.trim() || null, cfgModel.trim() || null)
      await refresh()
      setShowConfig(false)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const suggestions = [
    '最近是否发生过 DNS 故障？',
    '哪个进程的网络连接最多？',
    '最近的网络质量如何？',
    '当前有哪些代理和 VPN 在运行？',
  ]

  return (
    <div className="mx-auto flex h-full max-w-4xl flex-col gap-3 py-2">
      <div className="flex items-center justify-between">
        <h1 className="inline-flex items-center gap-2 text-xl font-semibold">
          <Sparkles className="h-5 w-5 text-ns-purple" /> AI Network Assistant
        </h1>
        <button
          onClick={() => setShowConfig((s) => !s)}
          className="rounded-md border border-ns-border px-2.5 py-1 text-xs text-ns-muted hover:text-ns-text"
        >
          {config ? `Provider: ${config.kind}${config.hasApiKey ? ' (已配置密钥)' : ''}` : '配置 Provider'}
        </button>
      </div>

      {showConfig && (
        <section className="rounded-lg border border-ns-border bg-ns-panel p-3 text-xs">
          <div className="mb-2 text-ns-muted">
            默认离线模式：不调用任何模型，仅输出检索到的证据摘要（不编造）。可切换 OpenAI 兼容端点
            （云端或本地模型如 Ollama http://127.0.0.1:11434/v1）。
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-ns-muted">
              类型
              <select
                value={cfgKind}
                onChange={(e) => setCfgKind(e.target.value)}
                className="mt-1 block rounded border border-ns-border bg-ns-bg px-2 py-1 text-ns-text"
              >
                <option value="offline">离线（仅证据）</option>
                <option value="openai">OpenAI 兼容 API</option>
              </select>
            </label>
            <label className="flex-1 text-ns-muted">
              Base URL
              <input
                value={cfgUrl}
                onChange={(e) => setCfgUrl(e.target.value)}
                placeholder="https://api.openai.com/v1 或 http://127.0.0.1:11434/v1"
                className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1 font-mono"
              />
            </label>
            <label className="w-32 text-ns-muted">
              模型
              <input
                value={cfgModel}
                onChange={(e) => setCfgModel(e.target.value)}
                placeholder="gpt-4o-mini / qwen2.5"
                className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1 font-mono"
              />
            </label>
            <label className="w-40 text-ns-muted">
              API Key（不回传明文）
              <input
                type="password"
                value={cfgKey}
                onChange={(e) => setCfgKey(e.target.value)}
                placeholder={config?.hasApiKey ? '已保存' : 'sk-...'}
                className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1 font-mono"
              />
            </label>
            <button
              onClick={() => void saveConfig()}
              disabled={busy}
              className="rounded-md border border-ns-accent/50 bg-ns-accent/10 px-3 py-1.5 text-ns-accent disabled:opacity-50"
            >
              保存
            </button>
          </div>
        </section>
      )}

      <div className="flex min-h-0 flex-1 flex-col overflow-auto rounded-lg border border-ns-border bg-ns-panel p-3">
        {history.length === 0 && (
          <div className="space-y-2 text-xs text-ns-muted">
            <p>
              助手只能访问 NetScope 已采集的结构化网络数据与诊断结果。回答流程：先检索证据 →
              再分析 → 引用时间与来源 → 区分事实与推测 → 证据不足时明确说明。
            </p>
            <div className="flex flex-wrap gap-1.5">
              {suggestions.map((s) => (
                <button
                  key={s}
                  onClick={() => setQuestion(s)}
                  className="rounded-full border border-ns-border px-2 py-0.5 hover:border-ns-accent/60 hover:text-ns-accent"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {[...history].reverse().map((c) => (
          <div key={c.id} className="mb-3 space-y-1.5">
            <div className="text-right">
              <span className="rounded-lg bg-ns-blue/20 px-2.5 py-1.5 text-xs text-ns-text">{c.question}</span>
            </div>
            <div className="whitespace-pre-wrap rounded-lg border border-ns-border bg-ns-bg px-3 py-2 text-xs leading-5 text-ns-text">
              {c.answer}
            </div>
            <div className="text-[10px] text-ns-muted">
              {formatDateTime(c.createdAt)} · {c.provider}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {error && <p className="text-xs text-ns-error">{error}</p>}
      <div className="flex gap-2">
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && void ask()}
          placeholder="例如：为什么我的 Google 打不开？"
          className="flex-1 rounded-md border border-ns-border bg-ns-panel px-3 py-2 text-xs text-ns-text outline-none placeholder:text-ns-muted"
        />
        <button
          onClick={() => void ask()}
          disabled={busy || !question.trim()}
          className="inline-flex items-center gap-1.5 rounded-md border border-ns-accent/50 bg-ns-accent/10 px-3 text-xs text-ns-accent disabled:opacity-40"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
        </button>
      </div>
    </div>
  )
}
