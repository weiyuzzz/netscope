import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { ConnectionEvent, GraphDiff, MetricsTick } from '../types/network'

/** 后台采集事件通道（后端 emit → 前端 store）。 */
export function onTopologyDiff(cb: (diff: GraphDiff) => void): Promise<UnlistenFn> {
  return listen<GraphDiff>('topology:diff', (e) => cb(e.payload))
}

export function onMetricsTick(cb: (tick: MetricsTick) => void): Promise<UnlistenFn> {
  return listen<MetricsTick>('metrics:tick', (e) => cb(e.payload))
}

export function onConnectionEvent(cb: (ev: ConnectionEvent) => void): Promise<UnlistenFn> {
  return listen<ConnectionEvent>('connection:event', (e) => cb(e.payload))
}
