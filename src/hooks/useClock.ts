import { useEffect, useState } from 'react'

/** 每秒更新的本地时钟，用于顶部栏“当前监控时间”。 */
export function useClock(): Date {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}
