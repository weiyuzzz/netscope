import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  type Node as RfNode,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { History, Pause, Play, Search } from 'lucide-react'
import {
  queryTimelineR3,
  replayTopology,
} from '../services/api'
import { formatDateTime } from '../utils/format'
import { useAppStore } from '../stores/appStore'
import type { TimelineEvent } from '../types/diagnostics'
import type { ReplayPayload } from '../types/diagnostics'

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

const KIND_COLOR: Record<string, string> = {
  conn_opened: 'text-ns-ok',
  conn_closed: 'text-ns-error',
  dns_new: 'text-ns-purple',
  interface_changed: 'text-ns-warn',
  ip_changed: 'text-ns-warn',
  route_changed: 'text-ns-warn',
  proxy_detected: 'text-ns-accent',
  proxy_removed: 'text-ns-error',
  quality_sample: 'text-ns-muted',
}

const FILTER_KINDS = [
  'conn_opened',
  'conn_closed',
  'dns_new',
  'proxy_detected',
  'proxy_removed',
  'interface_changed',
  'route_changed',
  'quality_sample',
]

function ReplayNode({ data }: NodeProps) {
  const d = data as { label: string; kind: string }
  return (
    <div className="min-w-[110px] rounded border border-ns-border bg-ns-panel px-2 py-1 text-[11px] text-ns-text">
      <Handle type="target" position={Position.Left} className="!bg-ns-muted" />
      {d.label}
      <Handle type="source" position={Position.Right} className="!bg-ns-muted" />
    </div>
  )
}

const nodeTypes = { replay: ReplayNode }

/** History & Replay：统一网络事件时间线 + 历史拓扑回放。 */
export function HistoryTimelinePage() {
  const focusTime = useAppStore((s) => s.focusTime)
  const setFocusTime = useAppStore((s) => s.setFocusTime)
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [search, setSearch] = useState('')
  const [kindFilter, setKindFilter] = useState<string | null>(null)
  const [replay, setReplay] = useState<ReplayPayload | null>(null)
  const [replayTime, setReplayTime] = useState('')
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const [busy, setBusy] = useState(false)
  const timer = useRef<number | null>(null)
  const doReplayRef = useRef<((at: string) => Promise<void>) | null>(null)

  const load = useCallback(async () => {
    const list = await queryTimelineR3({ limit: 400 }).catch(() => [])
    setEvents(list)
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  // 来自 Diagnostics Center 的联动：自动回放到指定时刻
  useEffect(() => {
    if (focusTime) {
      void doReplayRef.current?.(focusTime)
      setFocusTime(null)
    }
  }, [focusTime, setFocusTime])

  // 播放：沿事件时间推进回放
  useEffect(() => {
    if (!playing || events.length === 0) return
    timer.current = window.setInterval(() => {
      setReplayTime((prev) => {
        const idx = events.findIndex((e) => e.timestamp > prev)
        const next = idx >= 0 ? events[idx].timestamp : events[0].timestamp
        void replayTopology(next).then(setReplay).catch(() => {})
        return next
      })
    }, 1500 / speed)
    return () => {
      if (timer.current) window.clearInterval(timer.current)
    }
  }, [playing, speed, events])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return events.filter((e) => {
      if (kindFilter && e.kind !== kindFilter) return false
      if (q && !e.summary.toLowerCase().includes(q) && !e.kind.includes(q)) return false
      return true
    })
  }, [events, search, kindFilter])

  const doReplay = async (at: string) => {
    setBusy(true)
    try {
      setReplay(await replayTopology(at))
    } finally {
      setBusy(false)
    }
  }

  const rfNodes: RfNode[] = useMemo(() => {
    if (!replay) return []
    // 简单分层：按 id 前缀分列
    const layerOf = (id: string) => {
      if (id.startsWith('host')) return 0
      if (id.startsWith('adapter') || id.startsWith('gw') || id.startsWith('dns')) return 1
      if (id.startsWith('proxy')) return 2
      if (id.startsWith('process')) return 3
      return 4
    }
    const byLayer = new Map<number, typeof replay.nodes>()
    for (const n of replay.nodes) {
      const l = layerOf(n.id)
      if (!byLayer.has(l)) byLayer.set(l, [])
      byLayer.get(l)!.push(n)
    }
    const out: RfNode[] = []
    for (const [layer, list] of [...byLayer.entries()].sort((a, b) => a[0] - b[0])) {
      list.forEach((n, i) => {
        out.push({
          id: n.id,
          type: 'replay',
          position: { x: i * 190 + 40, y: layer * 110 + 30 },
          data: { label: n.label, kind: n.kind },
        })
      })
    }
    return out
  }, [replay])

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-ns-border px-3 py-2">
        <span className="inline-flex items-center gap-1.5 text-sm font-semibold">
          <History className="h-4 w-4 text-ns-accent" /> History
        </span>
        <div className="flex h-7 w-52 items-center gap-2 rounded-md border border-ns-border bg-ns-panel px-2">
          <Search className="h-3.5 w-3.5 text-ns-muted" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索摘要 / 类型"
            className="w-full bg-transparent text-xs text-ns-text outline-none placeholder:text-ns-muted"
          />
        </div>
        {FILTER_KINDS.map((k) => (
          <button
            key={k}
            onClick={() => setKindFilter((p) => (p === k ? null : k))}
            className={`rounded-full border px-2 py-0.5 text-[11px] ${
              kindFilter === k
                ? 'border-ns-accent/60 bg-ns-accent/10 text-ns-accent'
                : 'border-ns-border text-ns-muted hover:text-ns-text'
            }`}
          >
            {KIND_LABEL[k]}
          </button>
        ))}
        <span className="ml-auto text-xs text-ns-muted">{filtered.length} 条</span>
      </div>

      <div className="flex min-h-0 flex-1">
        {/* 时间线列表 */}
        <div className="min-w-0 flex-1 overflow-auto border-r border-ns-border">
          {filtered.map((e, i) => (
            <button
              key={`${e.timestamp}-${i}`}
              className="flex w-full items-baseline gap-2 border-b border-ns-border/40 px-3 py-1.5 text-left text-xs hover:bg-ns-panel-hover"
              onClick={() => void doReplay(e.timestamp)}
              title="回放该时刻拓扑"
            >
              <span className="shrink-0 font-mono text-ns-muted">{formatDateTime(e.timestamp)}</span>
              <span className={`shrink-0 ${KIND_COLOR[e.kind] ?? 'text-ns-muted'}`}>
                {KIND_LABEL[e.kind] ?? e.kind}
              </span>
              <span className="min-w-0 truncate text-ns-text">{e.summary}</span>
            </button>
          ))}
          {filtered.length === 0 && (
            <p className="p-6 text-center text-xs text-ns-muted">
              暂无历史事件（运行一段时间后自动积累）。
            </p>
          )}
        </div>

        {/* 回放面板 */}
        <div className="flex w-[46%] shrink-0 flex-col bg-ns-panel/40">
          <div className="flex items-center gap-2 border-b border-ns-border px-3 py-2">
            <span className="text-xs font-medium text-ns-accent">Network Replay</span>
            <button
              onClick={() => setPlaying((p) => !p)}
              disabled={events.length === 0}
              className="inline-flex items-center gap-1 rounded border border-ns-border px-2 py-0.5 text-[11px] text-ns-muted hover:text-ns-text disabled:opacity-40"
            >
              {playing ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
              {playing ? '暂停' : '播放'}
            </button>
            <select
              value={speed}
              onChange={(e) => setSpeed(Number(e.target.value))}
              className="rounded border border-ns-border bg-ns-bg px-1 py-0.5 text-[11px] text-ns-text"
            >
              <option value={1}>1x</option>
              <option value={2}>2x</option>
              <option value={4}>4x</option>
              <option value={8}>8x</option>
            </select>
            <button
              onClick={() => {
                setPlaying(false)
                setReplayTime(events[0]?.timestamp ?? '')
                if (events[0]) void doReplay(events[0].timestamp)
              }}
              className="text-[11px] text-ns-muted hover:text-ns-text"
            >
              ⏮ 单步（最早）
            </button>
            {busy && <span className="text-[11px] text-ns-muted">重建中…</span>}
            {replay && (
              <span className="ml-auto text-[11px] text-ns-muted">
                {formatDateTime(replay.at)} · {replay.appliedEvents} 事件
              </span>
            )}
          </div>
          {replay && replayTime && (
            <input
              type="range"
              min={0}
              max={Math.max(events.length - 1, 0)}
              value={Math.max(events.findIndex((e) => e.timestamp >= replayTime), 0)}
              onChange={(e) => {
                const ev = events[Number(e.target.value)]
                if (ev) {
                  setReplayTime(ev.timestamp)
                  void doReplay(ev.timestamp)
                }
              }}
              className="mx-3 mt-2 w-[calc(100%-24px)] accent-cyan-400"
            />
          )}
          <div className="relative min-h-0 flex-1">
            <ReactFlow
              nodes={rfNodes}
              edges={
                replay?.edges.map((e) => ({
                  id: e.id,
                  source: e.source,
                  target: e.target,
                  style: {
                    stroke: e.active ? '#3b82f6' : '#475569',
                    opacity: e.active ? 0.85 : 0.4,
                    strokeDasharray: e.active ? undefined : '5 4',
                  },
                })) ?? []
              }
              nodeTypes={nodeTypes}
              fitView
              minZoom={0.15}
              proOptions={{ hideAttribution: true }}
              nodesConnectable={false}
            >
              <Background color="#1e293b" gap={22} />
              <Controls showInteractive={false} className="!border-ns-border !bg-ns-panel [&_button]:!bg-ns-panel [&_button]:!text-ns-muted" />
            </ReactFlow>
            {replay && (
              <div className="absolute bottom-2 left-2 rounded bg-ns-panel/90 px-2 py-1 text-[10px] text-ns-muted">
                历史拓扑重建于 {formatDateTime(replay.at)}（基于当时保存的快照 + {replay.appliedEvents} 条事件，非当前状态）
              </div>
            )}
            {!replay && (
              <div className="absolute inset-0 flex items-center justify-center p-4 text-center text-xs text-ns-muted">
                点击左侧时间线事件，或点"播放"查看历史拓扑重建。
                <br />
                （需要拓扑快照积累约 30 秒）
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
