import { useCallback, useEffect, useState } from 'react'
import { Ban, Play, Save, Square } from 'lucide-react'
import {
  getCapturePackets,
  getCaptureStatus,
  getNpcapStatus,
  listCaptureDevices,
  startCapture,
  stopCapture,
} from '../services/api'
import { formatBytes, formatTime } from '../utils/format'
import type {
  CaptureConfig,
  CaptureDevice,
  CaptureStatus,
  NpcapStatus,
  PacketInfo,
} from '../types/diagnostics'

function protocolLabel(p: PacketInfo['protocol']): string {
  if (typeof p === 'string') return p.replace('icmp_v6', 'ICMPv6').toUpperCase()
  return `IP ${p.other}`
}

function metaLabel(meta: PacketInfo['meta']): string {
  switch (meta.type) {
    case 'tcp':
      return `TCP ${meta.flags.toString(16).padStart(2, '0').toUpperCase()} seq=${meta.seq}`
    case 'udp':
      return 'UDP'
    case 'icmp':
      return `ICMP type=${meta.kind} code=${meta.code}`
    case 'dns':
      return meta.is_response
        ? `DNS 响应 ${meta.domain ?? ''} → ${meta.answers.join(', ')}`
        : `DNS 查询 ${meta.domain ?? ''}`
    case 'tls':
      return meta.sni
        ? `TLS ${meta.stage === 'client_hello' ? 'ClientHello' : 'ServerHello'} SNI=${meta.sni}`
        : `TLS ${meta.stage}`
    case 'quic':
      return `QUIC ${meta.version ?? ''}`
    default:
      return ''
  }
}

/** Packet Inspector：Npcap 抓包（用户主动启用，含限制与导出）。 */
export function PacketInspectorPage() {
  const [npcap, setNpcap] = useState<NpcapStatus | null>(null)
  const [devices, setDevices] = useState<CaptureDevice[]>([])
  const [adapter, setAdapter] = useState<string>('')
  const [bpf, setBpf] = useState('')
  const [durationSecs, setDurationSecs] = useState(30)
  const [exportPath, setExportPath] = useState('')
  const [status, setStatus] = useState<CaptureStatus | null>(null)
  const [packets, setPackets] = useState<PacketInfo[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const s = await getCaptureStatus()
      setStatus(s)
      if (s.state === 'running' || s.state === 'stopped') {
        setPackets(await getCapturePackets(300))
      }
    } catch {
      /* 会话未初始化 */
    }
  }, [])

  useEffect(() => {
    void (async () => {
      const st = await getNpcapStatus()
      setNpcap(st)
      if (st.installed) {
        try {
          const devs = await listCaptureDevices()
          setDevices(devs)
          const first = devs.find((d) => !d.loopback) ?? devs[0]
          if (first) setAdapter(first.name)
        } catch (e) {
          setError(String(e))
        }
      }
    })()
    const timer = window.setInterval(() => void refresh(), 1000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const start = async () => {
    setBusy(true)
    setError(null)
    try {
      const device = devices.find((d) => d.name === adapter)
      const config: CaptureConfig = {
        adapter,
        adapterFriendly: device?.description ?? adapter,
        bpfFilter: bpf.trim() ? bpf.trim() : null,
        snaplen: 65535,
        maxBytes: 50 * 1024 * 1024,
        maxDurationSecs: durationSecs,
        maxPackets: 200_000,
      }
      const s = await startCapture(config, exportPath.trim() || null)
      setStatus(s)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const stop = async () => {
    setBusy(true)
    try {
      setStatus(await stopCapture())
      setPackets(await getCapturePackets(300))
    } finally {
      setBusy(false)
    }
  }

  const running = status?.state === 'running'

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <h1 className="text-xl font-semibold">Packet Inspector</h1>

      {npcap && !npcap.installed && (
        <div className="rounded-lg border border-ns-warn/40 bg-ns-warn/5 p-3 text-xs leading-5 text-ns-warn">
          <strong>Npcap 未安装。</strong>
          {npcap.hint}
          <div className="mt-1 text-ns-muted">
            抓包是可选模块：未安装时其余监控功能（连接 / 代理 / 拓扑 / 诊断）不受影响。
          </div>
        </div>
      )}

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">抓包控制（用户主动启用）</h2>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <label className="text-xs text-ns-muted">
            网卡
            <select
              value={adapter}
              onChange={(e) => setAdapter(e.target.value)}
              disabled={!npcap?.installed || running}
              className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            >
              {devices.map((d) => (
                <option key={d.name} value={d.name}>
                  {d.description ?? d.name} {d.loopback ? '（回环）' : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-ns-muted">
            BPF 过滤表达式（如 <code className="text-ns-accent">udp port 53</code>）
            <input
              value={bpf}
              onChange={(e) => setBpf(e.target.value)}
              disabled={running}
              placeholder="留空 = 全部流量"
              className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 font-mono text-xs text-ns-text"
            />
          </label>
          <label className="text-xs text-ns-muted">
            最长持续时间（秒，到时自动停止）
            <input
              type="number"
              min={5}
              max={600}
              value={durationSecs}
              onChange={(e) => setDurationSecs(Number(e.target.value))}
              disabled={running}
              className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 text-xs text-ns-text"
            />
          </label>
          <label className="text-xs text-ns-muted">
            PCAP 导出文件名（可选，保存到应用数据目录）
            <input
              value={exportPath}
              onChange={(e) => setExportPath(e.target.value)}
              disabled={running}
              placeholder="例如 capture-1.pcap"
              className="mt-1 w-full rounded border border-ns-border bg-ns-bg px-2 py-1.5 font-mono text-xs text-ns-text"
            />
          </label>
        </div>
        <div className="mt-3 flex items-center gap-2">
          {!running ? (
            <button
              onClick={() => void start()}
              disabled={!npcap?.installed || busy || !adapter}
              className="inline-flex items-center gap-1.5 rounded-md border border-ns-ok/50 bg-ns-ok/10 px-3 py-1.5 text-xs text-ns-ok disabled:opacity-40"
            >
              <Play className="h-3.5 w-3.5" /> 开始抓包
            </button>
          ) : (
            <button
              onClick={() => void stop()}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-md border border-ns-error/50 bg-ns-error/10 px-3 py-1.5 text-xs text-ns-error"
            >
              <Square className="h-3.5 w-3.5" /> 停止抓包
            </button>
          )}
          {status && (
            <span className="text-xs text-ns-muted">
              状态 {status.state} · 已捕获 {status.packets} 包 / {formatBytes(status.bytes)}
              {status.config && ` · 限制 ${status.config.maxDurationSecs ?? '-'}s`}
            </span>
          )}
          {status?.lastError && (
            <span className="inline-flex items-center gap-1 text-xs text-ns-error">
              <Ban className="h-3 w-3" /> {status.lastError}
            </span>
          )}
        </div>
        {error && <p className="mt-2 text-xs text-ns-error">{error}</p>}
        <p className="mt-2 text-[10px] leading-4 text-ns-muted">
          说明：抓包需要管理员权限（Npcap 默认限制适配器访问）。仅解析协议元数据，
          不解密 TLS、不保存载荷（PCAP 导出除外，需你主动配置文件名）。
        </p>
      </section>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 flex items-center gap-1.5 text-sm font-medium text-ns-accent">
          <Save className="h-4 w-4" /> 数据包（最近 {packets.length}）
        </h2>
        <div className="max-h-96 overflow-auto rounded border border-ns-border">
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-ns-panel text-ns-muted">
              <tr>
                <th className="px-2 py-1.5 font-medium">时间</th>
                <th className="px-2 py-1.5 font-medium">源</th>
                <th className="px-2 py-1.5 font-medium">目标</th>
                <th className="px-2 py-1.5 font-medium">协议</th>
                <th className="px-2 py-1.5 text-right font-medium">长度</th>
                <th className="px-2 py-1.5 font-medium">元数据</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((p, i) => (
                <tr key={`${p.timestamp}-${i}`} className="border-t border-ns-border/60">
                  <td className="whitespace-nowrap px-2 py-1 font-mono text-ns-muted">
                    {formatTime(p.timestamp)}
                  </td>
                  <td className="px-2 py-1 font-mono text-ns-text">
                    {p.srcIp}
                    {p.srcPort != null && `:${p.srcPort}`}
                  </td>
                  <td className="px-2 py-1 font-mono text-ns-text">
                    {p.dstIp}
                    {p.dstPort != null && `:${p.dstPort}`}
                  </td>
                  <td className="px-2 py-1">
                    <span className="rounded bg-ns-blue/15 px-1 text-[10px] text-ns-blue">
                      {protocolLabel(p.protocol)}
                    </span>
                  </td>
                  <td className="px-2 py-1 text-right tabular-nums text-ns-muted">{p.length}</td>
                  <td className="max-w-[320px] truncate px-2 py-1 text-ns-muted">
                    {metaLabel(p.meta)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {packets.length === 0 && (
            <div className="p-6 text-center text-xs text-ns-muted">
              {running ? '等待捕获数据包…' : '未在抓包。配置后点击"开始抓包"。'}
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
