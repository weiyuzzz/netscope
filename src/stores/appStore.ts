import { create } from 'zustand'
import type { CollectorStatus } from '../types/app'

export type PageId =
  | 'overview'
  | 'network-map'
  | 'connections'
  | 'proxy-analysis'
  | 'packet-inspector'
  | 'tcp-analytics'
  | 'route-explorer'
  | 'session-recorder'
  | 'history'
  | 'benchmark'
  | 'ai-assistant'
  | 'diagnostics'
  | 'settings'

interface AppState {
  currentPage: PageId
  setCurrentPage: (page: PageId) => void
  collectorStatus: CollectorStatus
  setCollectorStatus: (status: CollectorStatus) => void
  /** 从 Connections 跳转拓扑时携带的过滤词。 */
  focusFilter: string | null
  setFocusFilter: (value: string | null) => void
  focusTime: string | null
  setFocusTime: (value: string | null) => void
}

export const useAppStore = create<AppState>((set) => ({
  currentPage: 'overview',
  setCurrentPage: (currentPage) => set({ currentPage }),
  collectorStatus: 'not-initialized',
  setCollectorStatus: (collectorStatus) => set({ collectorStatus }),
  focusFilter: null,
  setFocusFilter: (focusFilter) => set({ focusFilter }),
  focusTime: null,
  setFocusTime: (focusTime) => set({ focusTime }),
}))
