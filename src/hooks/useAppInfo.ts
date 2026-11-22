import { useEffect, useState } from 'react'
import { getAppInfo } from '../services/api'
import type { AppInfo } from '../types/app'

/** 应用启动时从 Rust 后端获取真实应用与系统信息。 */
export function useAppInfo(): { info: AppInfo | null; error: string | null } {
  const [info, setInfo] = useState<AppInfo | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    getAppInfo()
      .then((v) => {
        if (!cancelled) setInfo(v)
      })
      .catch((e) => {
        if (!cancelled) setError(String(e))
      })
    return () => {
      cancelled = true
    }
  }, [])

  return { info, error }
}
