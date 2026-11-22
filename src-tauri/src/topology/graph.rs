//! 拓扑图容器：节点/边表 + 增量 diff 输出。
//!
//! 前端消费 `GraphDiff` 做增量更新（React Flow 上仅 patch 变化的节点/边），
//! 避免整图重建导致的闪烁与性能问题。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::models::topology::{TopologyEdge, TopologyNode};

/// 增量更新包（推送给前端的单位）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphDiff {
    pub upserted_nodes: Vec<TopologyNode>,
    pub upserted_edges: Vec<TopologyEdge>,
    pub removed_node_ids: Vec<String>,
    pub removed_edge_ids: Vec<String>,
}

impl GraphDiff {
    pub fn is_empty(&self) -> bool {
        self.upserted_nodes.is_empty()
            && self.upserted_edges.is_empty()
            && self.removed_node_ids.is_empty()
            && self.removed_edge_ids.is_empty()
    }
}

/// 拓扑图（Rust 侧权威状态）。
#[derive(Debug, Default)]
pub struct TopologyGraph {
    nodes: HashMap<String, TopologyNode>,
    edges: HashMap<String, TopologyEdge>,
}

impl TopologyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入或更新节点；返回是否有实际变化。
    pub fn upsert_node(&mut self, node: TopologyNode, diff: &mut GraphDiff) -> bool {
        let changed = match self.nodes.get(&node.id) {
            None => true,
            Some(old) => {
                old.label != node.label
                    || old.active != node.active
                    || old.last_seen != node.last_seen
                    || old.data != node.data
            }
        };
        diff.upserted_nodes.push(node.clone());
        self.nodes.insert(node.id.clone(), node);
        changed
    }

    /// 插入或更新边。
    pub fn upsert_edge(&mut self, edge: TopologyEdge, diff: &mut GraphDiff) -> bool {
        let changed = match self.edges.get(&edge.id) {
            None => true,
            Some(old) => {
                old.active != edge.active
                    || old.last_active != edge.last_active
                    || old.evidence != edge.evidence
            }
        };
        diff.upserted_edges.push(edge.clone());
        self.edges.insert(edge.id.clone(), edge);
        changed
    }

    /// 删除节点（级联删除关联边）。
    pub fn remove_node(&mut self, id: &str, diff: &mut GraphDiff) {
        if self.nodes.remove(id).is_some() {
            diff.removed_node_ids.push(id.to_string());
            let incident: Vec<String> = self
                .edges
                .values()
                .filter(|e| e.source == id || e.target == id)
                .map(|e| e.id.clone())
                .collect();
            for eid in incident {
                self.edges.remove(&eid);
                diff.removed_edge_ids.push(eid);
            }
        }
    }

    /// 批量移除边。
    pub fn remove_edge(&mut self, id: &str, diff: &mut GraphDiff) {
        if self.edges.remove(id).is_some() {
            diff.removed_edge_ids.push(id.to_string());
        }
    }

    pub fn node(&self, id: &str) -> Option<&TopologyNode> {
        self.nodes.get(id)
    }

    pub fn edge(&self, id: &str) -> Option<&TopologyEdge> {
        self.edges.get(id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &TopologyNode> {
        self.nodes.values()
    }

    pub fn edges(&self) -> impl Iterator<Item = &TopologyEdge> {
        self.edges.values()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// 将活跃边全部标记为非活跃并更新 diff（用于清理失效连接）。
    pub fn mark_edges_inactive(&mut self, edge_ids: &[String], diff: &mut GraphDiff) {
        for id in edge_ids {
            if let Some(e) = self.edges.get_mut(id) {
                if e.active {
                    e.active = false;
                    diff.upserted_edges.push(e.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::topology::{CorrelationEvidence, EdgeKind, NodeKind};
    use chrono::Utc;

    fn node(id: &str, kind: NodeKind) -> TopologyNode {
        let now = Utc::now();
        TopologyNode {
            id: id.into(),
            kind,
            label: id.into(),
            first_seen: now,
            last_seen: now,
            active: true,
            data: None,
        }
    }

    fn edge(id: &str, source: &str, target: &str) -> TopologyEdge {
        TopologyEdge {
            id: id.into(),
            source: source.into(),
            target: target.into(),
            kind: EdgeKind::ProcessRemoteIp,
            evidence: None,
            correlated_at: None,
            active: true,
            last_active: None,
                data: None,
        }
    }

    #[test]
    fn remove_node_cascades_edges() {
        let mut g = TopologyGraph::new();
        let mut diff = GraphDiff::default();
        g.upsert_node(node("process:1", NodeKind::Process), &mut diff);
        g.upsert_node(node("ip:1.2.3.4", NodeKind::RemoteIp), &mut diff);
        g.upsert_edge(edge("edge:proc-ip:1:1.2.3.4", "process:1", "ip:1.2.3.4"), &mut diff);

        let mut diff2 = GraphDiff::default();
        g.remove_node("process:1", &mut diff2);
        assert_eq!(diff2.removed_node_ids, vec!["process:1"]);
        assert_eq!(
            diff2.removed_edge_ids,
            vec!["edge:proc-ip:1:1.2.3.4"],
            "删除节点应级联删除关联边"
        );
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn domain_ip_edge_keeps_evidence() {
        let mut g = TopologyGraph::new();
        let mut diff = GraphDiff::default();
        let now = Utc::now();
        let mut e = edge("edge:domain-ip:a.com:1.1.1.1", "domain:a.com", "ip:1.1.1.1");
        e.kind = EdgeKind::DomainIp;
        e.evidence = Some(CorrelationEvidence::DnsThenConnect);
        e.correlated_at = Some(now);
        g.upsert_edge(e, &mut diff);
        let stored = g.edge("edge:domain-ip:a.com:1.1.1.1").unwrap();
        assert_eq!(stored.evidence, Some(CorrelationEvidence::DnsThenConnect));
    }
}
