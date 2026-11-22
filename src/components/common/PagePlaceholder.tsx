import type { ReactNode } from 'react'

interface PagePlaceholderProps {
  title: string
  phase: string
  description: string
  children?: ReactNode
}

/** 未实现模块的占位页：如实标注所属阶段，不使用任何模拟数据。 */
export function PagePlaceholder({
  title,
  phase,
  description,
  children,
}: PagePlaceholderProps) {
  return (
    <div className="mx-auto max-w-3xl space-y-4 pt-8">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold">{title}</h1>
        <span className="rounded border border-ns-border bg-ns-panel px-2 py-0.5 text-xs text-ns-accent">
          {phase}
        </span>
      </div>
      <div className="rounded-lg border border-ns-border bg-ns-panel p-4 text-sm leading-6 text-ns-muted">
        <p>{description}</p>
        {children}
      </div>
    </div>
  )
}
