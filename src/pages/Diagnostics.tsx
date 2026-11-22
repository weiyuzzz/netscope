import { PagePlaceholder } from '../components/common/PagePlaceholder'

/** Diagnostics 诊断页。Phase 4 实现 Ping / DNS / Traceroute。 */
export function DiagnosticsPage() {
  return (
    <PagePlaceholder
      title="Diagnostics"
      phase="Phase 4 实现"
      description="基础网络诊断：Ping、DNS 查询测试、Traceroute、默认网关连通性测试、
      公网 IP 查询（需用户主动触发）、连接超时检测。展示延迟、丢包率、每跳 IP 与响应时间。
      对不响应 ICMP 的节点将如实显示超时/无响应，不判定为故障。"
    />
  )
}
