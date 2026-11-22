import { useEffect, useState } from 'react'
import { useAppInfo } from '../hooks/useAppInfo'
import {
  clearHistory,
  getCollectionSettings,
  setCollectionEnabled,
  setCollectInterval,
} from '../services/api'
import type { CollectionSettings } from '../types/network'

/** Settings：采集开关 / 刷新间隔 / 历史清理 / 版本信息。 */
export function SettingsPage() {
  const { info } = useAppInfo()
  const [settings, setSettings] = useState<CollectionSettings | null>(null)
  const [saved, setSaved] = useState<string | null>(null)

  useEffect(() => {
    void getCollectionSettings().then(setSettings).catch(() => setSettings(null))
  }, [])

  const flash = (msg: string) => {
    setSaved(msg)
    window.setTimeout(() => setSaved(null), 2500)
  }

  const toggleCollection = async () => {
    if (!settings) return
    const next = !settings.enabled
    await setCollectionEnabled(next)
    setSettings({ ...settings, enabled: next })
    flash(next ? '采集已开启' : '采集已暂停')
  }

  const changeInterval = async (secs: number) => {
    if (!settings) return
    await setCollectInterval(secs)
    setSettings({ ...settings, intervalSecs: secs })
    flash(`采集间隔已设为 ${secs} 秒`)
  }

  const doClear = async () => {
    if (window.confirm('确认清除 7 天前的本地历史数据？（活跃连接状态保留）')) {
      await clearHistory(7)
      flash('历史数据已清除')
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-xl font-semibold">Settings</h1>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">数据采集</h2>
        {settings ? (
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-ns-text">后台采集</span>
              <button
                onClick={() => void toggleCollection()}
                className={`rounded-md border px-3 py-1 text-xs ${
                  settings.enabled
                    ? 'border-ns-ok/50 bg-ns-ok/10 text-ns-ok'
                    : 'border-ns-border text-ns-muted'
                }`}
              >
                {settings.enabled ? '运行中 · 点击暂停' : '已暂停 · 点击开启'}
              </button>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-ns-text">采集间隔</span>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={1}
                  max={15}
                  value={settings.intervalSecs}
                  onChange={(e) => void changeInterval(Number(e.target.value))}
                  className="w-40 accent-cyan-400"
                />
                <span className="w-12 text-right text-xs tabular-nums text-ns-muted">
                  {settings.intervalSecs}s
                </span>
              </div>
            </div>
            <p className="text-[10px] leading-4 text-ns-muted">
              轻量级系统事件采集为默认模式；Npcap 抓包为独立可选模块（Packet Inspector
              页面用户手动启用），不会随本开关持续运行。
            </p>
          </div>
        ) : (
          <p className="text-xs text-ns-muted">设置加载中…</p>
        )}
        {saved && <p className="mt-2 text-xs text-ns-ok">{saved}</p>}
      </section>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-ns-accent">本地数据</h2>
        <div className="flex items-center justify-between text-sm">
          <span className="text-ns-text">清除历史数据</span>
          <button
            onClick={() => void doClear()}
            className="rounded-md border border-ns-error/40 px-3 py-1 text-xs text-ns-error hover:bg-ns-error/10"
          >
            清除 7 天前数据
          </button>
        </div>
        <p className="mt-2 text-[10px] leading-4 text-ns-muted">
          仅保存网络元数据（连接 / 事件 / 指标），不保存数据包内容。数据库位于系统应用数据目录。
        </p>
      </section>

      <section className="rounded-lg border border-ns-border bg-ns-panel p-4">
        <h2 className="mb-2 text-sm font-medium text-ns-accent">版本信息</h2>
        <p className="text-sm text-ns-text">
          {info ? `NetScope v${info.version} · ${info.os} (${info.arch})` : '加载中…'}
        </p>
      </section>
    </div>
  )
}
