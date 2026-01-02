use super::NodePrint;
use crate::{DepKind, Kid, Krates};
use anyhow::Context;
use krates::{Edge, Node, petgraph as pg};
use std::collections::{HashSet, VecDeque};

#[derive(serde::Serialize)]
pub struct GraphNode {
    #[serde(flatten)]
    inner: NodeInner,
    #[serde(skip_serializing_if = "is_false")]
    repeat: bool,
    #[serde(skip_serializing_if = "is_empty")]
    parents: Vec<GraphNode>,
}

#[derive(serde::Serialize)]
pub enum NodeInner {
    Krate {
        name: String,
        version: semver::Version,
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<&'static str>,
        #[serde(skip)]
        id: Kid,
        #[serde(skip)]
        is_project_crate: bool,
    },
    Feature {
        crate_name: String,
        name: String,
    },
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !v
}

#[allow(clippy::ptr_arg)]
fn is_empty(v: &Vec<GraphNode>) -> bool {
    v.is_empty()
}

/// Provides the `InclusionGrapher::write_graph` method which creates a reverse
/// dependency graph rooted at a specific node
pub struct InclusionGrapher<'a> {
    pub krates: &'a Krates,
}

impl<'a> InclusionGrapher<'a> {
    pub fn new(krates: &'a Krates) -> Self {
        Self { krates }
    }

    /// Check if this crate is a project crate, single project roots are added to workspace members
    fn is_project_crate(&self, kid: &Kid) -> bool {
        self.krates.workspace_members().any(|wm| {
            let krates::Node::Krate { id, .. } = wm else {
                return false;
            };
            id == kid
        })
    }

    /// Creates an inclusion graph rooted at the specified node.
    pub fn build_graph(
        &self,
        id: &super::GraphNode,
        max_feature_depth: usize,
    ) -> anyhow::Result<GraphNode> {
        let mut visited = HashSet::new();

        let (node_id, _node) = self
            .krates
            .get_node(&id.kid, id.feature.as_deref())
            .context("unable to find node")?;

        let np = NodePrint {
            node: node_id,
            edge: None,
        };

        let root = self.append_node(np, 0, max_feature_depth, &mut visited)?;

        // If the graph was rooted on a feature node, we want to use that as the
        // root when building the graph, but want the actual crate the feature
        // belongs to be the root of the graph the user sees
        if id.feature.is_some() {
            let (_id, root_krate) = self.krates.get_node(&id.kid, None).with_context(|| {
                format!(
                    "graph was built but we were unable to find the node for {}",
                    id.kid
                )
            })?;

            let inner = if let Node::Krate { krate, .. } = root_krate {
                NodeInner::Krate {
                    name: krate.name.clone(),
                    version: krate.version.clone(),
                    kind: None,
                    id: krate.id.clone(),
                    is_project_crate: self.is_project_crate(&krate.id),
                }
            } else {
                anyhow::bail!("unable to find crate node for {}", id.kid);
            };

            Ok(GraphNode {
                inner,
                repeat: false,
                parents: vec![root],
            })
        } else {
            Ok(root)
        }
    }

    fn make_node(&self, np: NodePrint) -> NodeInner {
        match &self.krates.graph()[np.node] {
            Node::Krate { krate, .. } => {
                let kind = np.edge.and_then(|eid| match self.krates.graph()[eid] {
                    Edge::Dep { kind, .. } | Edge::DepFeature { kind, .. } => match kind {
                        DepKind::Normal => None,
                        DepKind::Dev => Some("dev"),
                        DepKind::Build => Some("build"),
                    },
                    Edge::Feature => None,
                });

                NodeInner::Krate {
                    name: krate.name.clone(),
                    version: krate.version.clone(),
                    kind,
                    id: krate.id.clone(),
                    is_project_crate: self.is_project_crate(&krate.id),
                }
            }
            Node::Feature { name, krate_index } => {
                let crate_name =
                    if let Node::Krate { krate, .. } = &self.krates.graph()[*krate_index] {
                        krate.name.clone()
                    } else {
                        "".to_owned()
                    };

                NodeInner::Feature {
                    crate_name,
                    name: name.clone(),
                }
            }
        }
    }

    fn append_node(
        &self,
        np: NodePrint,
        depth: usize,
        max_feature_depth: usize,
        visited: &mut HashSet<krates::NodeId>,
    ) -> anyhow::Result<GraphNode> {
        use pg::visit::EdgeRef;

        if !visited.insert(np.node) {
            return Ok(GraphNode {
                inner: self.make_node(np),
                repeat: true,
                parents: Vec::new(),
            });
        }

        let mut node_parents = smallvec::SmallVec::<[NodePrint; 10]>::new();
        let graph = self.krates.graph();

        if depth < max_feature_depth {
            node_parents.extend(graph.edges_directed(np.node, pg::Direction::Incoming).map(
                |edge| NodePrint {
                    node: edge.source(),
                    edge: Some(edge.id()),
                },
            ));
        } else {
            // If we're not adding features we need to walk up any feature edges
            // until we reach an actual crate dependenc

            node_parents.extend(
                self.krates
                    .direct_dependents(np.node)
                    .into_iter()
                    .map(|dd| NodePrint {
                        node: dd.node_id,
                        edge: Some(dd.edge_id),
                    }),
            );
        }

        let parents = if !node_parents.is_empty() {
            // Resolve uses Hash data types internally but we want consistent output ordering
            node_parents.sort_by(|a, b| match (&graph[a.node], &graph[b.node]) {
                (Node::Krate { krate: a, .. }, Node::Krate { krate: b, .. }) => a.id.cmp(&b.id),
                (Node::Krate { .. }, Node::Feature { .. }) => std::cmp::Ordering::Less,
                (Node::Feature { .. }, Node::Krate { .. }) => std::cmp::Ordering::Greater,
                (Node::Feature { name: a, .. }, Node::Feature { name: b, .. }) => a.cmp(b),
            });

            let mut parents = Vec::with_capacity(node_parents.len());

            for parent in node_parents {
                let pnode = self.append_node(parent, depth + 1, max_feature_depth, visited)?;
                parents.push(pnode);
            }

            parents
        } else {
            Vec::new()
        };

        Ok(GraphNode {
            inner: self.make_node(np),
            repeat: false,
            parents,
        })
    }
}

use super::{Diag, FileId, Files, Severity};

pub type CsDiag = codespan_reporting::diagnostic::Diagnostic<FileId>;

pub fn cs_diag_to_json(diag: CsDiag, files: &Files) -> serde_json::Value {
    let mut val = serde_json::json!({
        "type": "diagnostic",
        "fields": {
            "severity": match diag.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Note => "note",
                Severity::Help => "help",
                Severity::Bug => "bug",
            },
            "message": diag.message,
        },
    });

    {
        let obj = val.as_object_mut().unwrap();
        let obj = obj.get_mut("fields").unwrap().as_object_mut().unwrap();

        if let Some(code) = diag.code {
            obj.insert("code".to_owned(), serde_json::Value::String(code));
        }

        if !diag.labels.is_empty() {
            let mut labels = Vec::with_capacity(diag.labels.len());

            for label in diag.labels {
                let location = files
                    .location(label.file_id, label.range.start as u32)
                    .unwrap();
                labels.push(serde_json::json!({
                    "message": label.message,
                    "span": files.source(label.file_id)[label.range].trim_matches('"'),
                    "line": location.line.to_usize() + 1,
                    "column": location.column.to_usize() + 1,
                }));
            }

            obj.insert("labels".to_owned(), serde_json::Value::Array(labels));
        }

        if !diag.notes.is_empty() {
            obj.insert(
                "notes".to_owned(),
                serde_json::Value::Array(
                    diag.notes
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }

    val
}

pub fn diag_to_json(
    diag: Diag,
    files: &Files,
    grapher: Option<&InclusionGrapher<'_>>,
) -> serde_json::Value {
    let mut to_print = cs_diag_to_json(diag.diag, files);

    let obj = to_print.as_object_mut().unwrap();
    let fields = obj.get_mut("fields").unwrap().as_object_mut().unwrap();

    if let Some(grapher) = &grapher {
        let mut graphs = Vec::new();
        for gn in diag.graph_nodes {
            if let Ok(graph) =
                grapher.build_graph(&gn, if diag.with_features { usize::MAX } else { 0 })
                && let Ok(sgraph) = serde_json::value::to_value(graph)
            {
                graphs.push(sgraph);
            }
        }

        fields.insert("graphs".to_owned(), serde_json::Value::Array(graphs));
    }

    if let Some(extra) = diag.extra {
        let key = extra.key();
        if let Ok(val) = serde_json::to_value(extra) {
            fields.insert(key.into(), val);
        }
    }

    to_print
}

pub fn write_graph_as_text(root: &GraphNode) -> String {
    write_graph_as_text_internal(root, false)
}

pub fn write_compact_graph_as_text(root: &GraphNode) -> String {
    write_graph_as_text_internal(root, true)
}

fn write_graph_as_text_internal(root: &GraphNode, stop_at_project_crate: bool) -> String {
    use std::fmt::Write;

    const DWN: char = '│';
    const TEE: char = '├';
    const ELL: char = '└';
    const RGT: char = '─';

    let mut out = String::with_capacity(256);
    let mut levels = smallvec::SmallVec::<[bool; 10]>::new();

    fn write(
        node: &GraphNode,
        out: &mut String,
        levels_continue: &mut smallvec::SmallVec<[bool; 10]>,
        stop_at_project_crate: bool,
    ) {
        let star = if !node.repeat { "" } else { " (*)" };

        if let Some((&last_continues, rest)) = levels_continue.split_last() {
            for &continues in rest {
                let c = if continues { DWN } else { ' ' };
                write!(out, "{c}   ").unwrap();
            }

            let c = if last_continues { TEE } else { ELL };
            write!(out, "{c}{RGT}{RGT} ").unwrap();
        }

        match &node.inner {
            NodeInner::Krate {
                name,
                version,
                kind,
                is_project_crate,
                ..
            } => {
                if let Some(kind) = kind {
                    write!(out, "({kind}) ").unwrap();
                }

                writeln!(out, "{name} v{version}{star}").unwrap();

                // Stop traversing if this is a workspace member and compact mode is enabled
                if stop_at_project_crate && *is_project_crate {
                    return;
                }
            }
            NodeInner::Feature { crate_name, name } => {
                writeln!(out, "{crate_name} feature '{name}' {star}").unwrap();
            }
        }

        if node.parents.is_empty() {
            return;
        }

        let cont = node.parents.len() - 1;

        for (i, parent) in node.parents.iter().enumerate() {
            levels_continue.push(i < cont);
            write(parent, out, levels_continue, stop_at_project_crate);
            levels_continue.pop();
        }
    }

    write(root, &mut out, &mut levels, stop_at_project_crate);
    out
}

#[derive(Debug, Clone)]
pub struct DependencyPath {
    pub root: (String, semver::Version),
    pub root_kid: Kid,
    pub crates: Vec<(String, semver::Version, Kid)>,
    pub is_project_crate: bool,
}

impl GraphNode {
    pub fn collect_project_paths(&self) -> Vec<DependencyPath> {
        let mut paths = Vec::new();
        let mut current_path = VecDeque::new();
        self.collect_root_paths_internal(&mut paths, &mut current_path);
        paths
    }

    fn collect_root_paths_internal(
        &self,
        paths: &mut Vec<DependencyPath>,
        current_path: &mut VecDeque<(String, semver::Version, Kid)>,
    ) {
        let (current_name, current_version, current_kid, is_project_crate) = 
            match &self.inner {
                NodeInner::Krate { name, version, id, is_project_crate, .. } => {
                    (name.clone(), version.clone(), id.clone(), *is_project_crate)
                }
                NodeInner::Feature { .. } => {
                    for parent in &self.parents {
                        parent.collect_root_paths_internal(paths, current_path);
                    }
                    return;
                }
            };

        if is_project_crate {
            paths.push(DependencyPath {
                root: (current_name, current_version),
                root_kid: current_kid,
                crates: current_path.iter().cloned().collect(),
                is_project_crate,
            });
        } else {
            let current_crate = (current_name.clone(), current_version.clone(), current_kid.clone());

            for parent in &self.parents {
                match &parent.inner {
                    NodeInner::Krate { .. } => {
                        current_path.push_front(current_crate.clone());
                        parent.collect_root_paths_internal(paths, current_path);
                        current_path.pop_front();
                    }
                    NodeInner::Feature { .. } => {
                        parent.collect_root_paths_internal(paths, current_path);
                    }
                }
            }
        }
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::KrateGather;

    #[test]
    fn test_write_graph_as_text_simple() {
        let krates = KrateGather::new("duplicates").gather();
        let grapher = InclusionGrapher::new(&krates);

        // Find a crate to build a graph for
        let krate = krates.krates().next().expect("test fixture should have at least one crate");
        let graph_node = super::super::GraphNode {
            kid: krate.id.clone(),
            feature: None,
        };

        let graph = grapher.build_graph(&graph_node, 0).expect("should be able to build graph");
        let text = write_graph_as_text(&graph);
        // Should contain the crate name
        assert!(text.contains(&krate.name));
        assert!(text.contains(&krate.version.to_string()));
    }

    #[test]
    fn test_write_compact_graph_as_text() {
        let krates = KrateGather::new("workspace").gather();
        let grapher = InclusionGrapher::new(&krates);

        // Find a non-workspace crate to build a graph for
        let krate = krates.krates().find(|k| {
            !krates.workspace_members().any(|wm| {
                if let krates::Node::Krate { id, .. } = wm {
                    id == &k.id
                } else {
                    false
                }
            })
        }).expect("test fixture should have at least one non-workspace crate");

        let graph_node = super::super::GraphNode {
            kid: krate.id.clone(),
            feature: None,
        };

        let graph = grapher.build_graph(&graph_node, 0)
            .expect("should be able to build graph");
        let normal_text = write_graph_as_text(&graph);
        let compact_text = write_compact_graph_as_text(&graph);

        // Compact should be shorter or equal (stops at project crates)
        // Both should contain the root crate
        assert!(normal_text.contains(&krate.name));
        assert!(compact_text.contains(&krate.name));
        assert!(
            compact_text.len() <= normal_text.len(),
            "compact text should be shorter or equal to normal text"
        );

        // Snapshot both graph outputs for verification
        insta::assert_snapshot!("normal_graph_text", normal_text);
        insta::assert_snapshot!("compact_graph_text", compact_text);
    }

    #[test]
    fn test_collect_root_paths() {
        let krates = KrateGather::new("workspace").gather();
        let grapher = InclusionGrapher::new(&krates);

        // Find a non-workspace crate
        let krate = krates.krates().find(|k| {
            !krates.workspace_members().any(|wm| {
                if let krates::Node::Krate { id, .. } = wm {
                    id == &k.id
                } else {
                    false
                }
            })
        }).expect("test fixture should have at least one non-workspace crate");

        let graph_node = super::super::GraphNode {
            kid: krate.id.clone(),
            feature: None,
        };

        let graph = grapher.build_graph(&graph_node, 0)
            .expect("should be able to build graph");
        let graph_text = write_graph_as_text(&graph);
        let paths = graph.collect_project_paths();

        // Snapshot the full graph for verification
        insta::assert_snapshot!("collect_root_paths_graph", graph_text);

        // Should have exactly 2 paths to workspace members: member-one and member-two
        assert_eq!(paths.len(), 2, "should have exactly 2 paths to workspace members");
        assert!(paths.iter().any(|p| p.root.0 == "member-one"), "should have path to member-one");
        assert!(paths.iter().any(|p| p.root.0 == "member-two"), "should have path to member-two");
    }

    #[test]
    fn test_build_graph_with_features() {
        let krates = KrateGather::new("features").gather();
        let grapher = InclusionGrapher::new(&krates);

        // Find a crate with features
        let krate = krates.krates().next().expect("test fixture should have at least one crate");
        let graph_node = super::super::GraphNode {
            kid: krate.id.clone(),
            feature: None,
        };

        // Build graph without features
        let graph_no_features = grapher.build_graph(&graph_node, 0)
            .expect("should be able to build graph without features");
        // Build graph with features (max depth)
        let graph_with_features = grapher.build_graph(&graph_node, usize::MAX)
            .expect("should be able to build graph with features");

        // Graph with features might be larger (more nodes)
        // But both should contain the root crate
        let text_no_features = write_graph_as_text(&graph_no_features);
        let text_with_features = write_graph_as_text(&graph_with_features);

        insta::assert_snapshot!("build_graph_without_features", text_no_features);
        insta::assert_snapshot!("build_graph_with_features", text_with_features);

        assert!(text_no_features.contains(&krate.name));
        assert!(text_with_features.contains(&krate.name));
    }

    #[test]
    fn test_build_graph_feature_node() {
        let krates = KrateGather::new("features").gather();
        let grapher = InclusionGrapher::new(&krates);

        // Find a crate and one of its features
        let mut found_feature = None;
        let graph = krates.graph();
        for node_id in graph.node_indices() {
            if let krates::Node::Feature { name, krate_index } = &graph[node_id] {
                if let krates::Node::Krate { id, .. } = &graph[*krate_index] {
                    // Find the corresponding krate
                    if let Some(krate) = krates.krates().find(|k| k.id == *id) {
                        found_feature = Some((krate, name.clone()));
                        break;
                    }
                }
            }
        }

        let (krate, feature_name) = found_feature.expect("test fixture should have at least one feature");
        let graph_node = super::super::GraphNode {
            kid: krate.id.clone(),
            feature: Some(feature_name),
        };

        // Should be able to build graph from feature
        let graph = grapher.build_graph(&graph_node, 0)
            .expect("should be able to build graph from feature node");
        let text = write_graph_as_text(&graph);
        insta::assert_snapshot!("build_graph_feature_node", text);
        // Should contain the crate name (not the feature as root)
        assert!(text.contains(&krate.name));
    }

    #[test]
    fn test_graph_node_repeat_detection() {
        // Create a simple manual graph structure to test repeat detection
        // Use Kid::default() for test purposes
        let root = GraphNode {
            inner: NodeInner::Krate {
                name: "root".to_string(),
                version: semver::Version::parse("1.0.0").unwrap(),
                kind: None,
                id: Kid::default(),
                is_project_crate: false,
            },
            repeat: false,
            parents: vec![
                GraphNode {
                    inner: NodeInner::Krate {
                        name: "dep1".to_string(),
                        version: semver::Version::parse("1.0.0").unwrap(),
                        kind: None,
                        id: Kid::default(),
                        is_project_crate: false,
                    },
                    repeat: false,
                    parents: vec![
                        GraphNode {
                            inner: NodeInner::Krate {
                                name: "dep2".to_string(),
                                version: semver::Version::parse("1.0.0").unwrap(),
                                kind: None,
                                id: Kid::default(),
                                is_project_crate: false,
                            },
                            repeat: false,
                            parents: vec![],
                        },
                        // Repeat of dep2
                        GraphNode {
                            inner: NodeInner::Krate {
                                name: "dep2".to_string(),
                                version: semver::Version::parse("1.0.0").unwrap(),
                                kind: None,
                                id: Kid::default(),
                                is_project_crate: false,
                            },
                            repeat: true,
                            parents: vec![],
                        },
                    ],
                },
            ],
        };

        let text = write_graph_as_text(&root);
        // Should contain the repeat marker
        assert!(text.contains("(*)"));
        // Should contain all crate names
        assert!(text.contains("root"));
        assert!(text.contains("dep1"));
        assert!(text.contains("dep2"));
    }

    #[test]
    fn test_graph_node_with_dep_kinds() {
        // Test that dev and build dependencies are marked correctly
        let root = GraphNode {
            inner: NodeInner::Krate {
                name: "root".to_string(),
                version: semver::Version::parse("1.0.0").unwrap(),
                kind: None,
                id: Kid::default(),
                is_project_crate: false,
            },
            repeat: false,
            parents: vec![
                GraphNode {
                    inner: NodeInner::Krate {
                        name: "dev-dep".to_string(),
                        version: semver::Version::parse("1.0.0").unwrap(),
                        kind: Some("dev"),
                        id: Kid::default(),
                        is_project_crate: false,
                    },
                    repeat: false,
                    parents: vec![],
                },
                GraphNode {
                    inner: NodeInner::Krate {
                        name: "build-dep".to_string(),
                        version: semver::Version::parse("1.0.0").unwrap(),
                        kind: Some("build"),
                        id: Kid::default(),
                        is_project_crate: false,
                    },
                    repeat: false,
                    parents: vec![],
                },
            ],
        };

        let text = write_graph_as_text(&root);
        assert!(text.contains("(dev)"));
        assert!(text.contains("(build)"));
        assert!(text.contains("dev-dep"));
        assert!(text.contains("build-dep"));
    }

    #[test]
    fn test_collect_root_paths_empty() {
        // Test with a graph that has no paths to project crates
        let root = GraphNode {
            inner: NodeInner::Krate {
                name: "standalone".to_string(),
                version: semver::Version::parse("1.0.0").unwrap(),
                kind: None,
                id: Kid::default(),
                is_project_crate: false,
            },
            repeat: false,
            parents: vec![],
        };

        let paths = root.collect_project_paths();
        // Should be empty since there are no project crates in the path
        assert!(paths.is_empty());
    }

    #[test]
    fn test_collect_root_paths_with_project_crate() {
        // Test with a graph that ends at a project crate
        // Use real krates to get valid Kid instances
        let krates = KrateGather::new("workspace").gather();
        let grapher = InclusionGrapher::new(&krates);

        // Find a non-workspace crate that might have dependencies
        let krate = krates.krates().find(|k| {
            !krates.workspace_members().any(|wm| {
                if let krates::Node::Krate { id, .. } = wm {
                    id == &k.id
                } else {
                    false
                }
            })
        }).expect("test fixture should have at least one non-workspace crate");

        let graph_node = super::super::GraphNode {
            kid: krate.id.clone(),
            feature: None,
        };

        let graph = grapher.build_graph(&graph_node, 0)
            .expect("should be able to build graph");
        let paths = graph.collect_project_paths();
        
        // Should have paths to workspace members if the dependency structure allows it
        // Verify that all paths have valid structure
        for path in &paths {
            assert!(!path.root.0.is_empty(), "path root name should not be empty");
            assert_eq!(path.root.0, path.root_kid.name(), "path root name should match kid name");
            assert!(path.is_project_crate, "all paths should end at project crates");
        }
        
        // If there are workspace members, we should get at least one path
        // (This test is more general than test_collect_root_paths which expects exactly 2)
        if !krates.workspace_members().next().is_none() {
            assert!(!paths.is_empty(), "should have at least one path to workspace member");
        }
    }

    #[test]
    fn test_graph_node_with_features() {
        let root = GraphNode {
            inner: NodeInner::Krate {
                name: "root".to_string(),
                version: semver::Version::parse("1.0.0").unwrap(),
                kind: None,
                id: Kid::default(),
                is_project_crate: false,
            },
            repeat: false,
            parents: vec![
                GraphNode {
                    inner: NodeInner::Feature {
                        crate_name: "some-crate".to_string(),
                        name: "some-feature".to_string(),
                    },
                    repeat: false,
                    parents: vec![
                        GraphNode {
                            inner: NodeInner::Krate {
                                name: "some-crate".to_string(),
                                version: semver::Version::parse("1.0.0").unwrap(),
                                kind: None,
                                id: Kid::default(),
                                is_project_crate: false,
                            },
                            repeat: false,
                            parents: vec![],
                        },
                    ],
                },
            ],
        };

        let text = write_graph_as_text(&root);
        assert!(text.contains("some-crate"));
        assert!(text.contains("some-feature"));
        assert!(text.contains("feature"));
    }

    #[test]
    fn test_empty_graph() {
        let root = GraphNode {
            inner: NodeInner::Krate {
                name: "root".to_string(),
                version: semver::Version::parse("1.0.0").unwrap(),
                kind: None,
                id: Kid::default(),
                is_project_crate: false,
            },
            repeat: false,
            parents: vec![],
        };

        let text = write_graph_as_text(&root);
        assert!(text.contains("root"));
        assert!(text.contains("1.0.0"));

        let paths = root.collect_project_paths();
        assert!(paths.is_empty());
    }
}
