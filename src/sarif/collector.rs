use crate::diag::Extra;
use crate::sarif::model::{
    DefaultConfiguration, Driver, Help, Location, LogicalLocation, Message, Result as SarifResult,
    Rule, RuleProperties, Run, SarifLog, TextContent, Tool,
};
use crate::{
    Kid, Krates,
    diag::{self, DiagnosticCode, Pack, Severity},
};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use krates::Node;

/// Collects diagnostics and converts them to SARIF format
pub struct SarifCollector {
    diagnostics: Vec<DiagnosticData>,
    rules: BTreeMap<DiagnosticCode, RuleData>,
}

struct DiagnosticData {
    code: DiagnosticCode,
    severity: Severity,
    krates: smallvec::SmallVec<[Kid; 2]>,
    message: Message,
    locations: Vec<Location>,
    extra: Option<diag::Extra>,
}

struct RuleData {
    code: DiagnosticCode,
    severity: Severity,
    description: &'static str,
}

#[allow(clippy::derivable_impls)]
impl Default for SarifCollector {
    fn default() -> Self {
        Self {
            diagnostics: Vec::new(),
            rules: BTreeMap::new(),
        }
    }
}

impl SarifCollector {
    pub fn add_diagnostics(&mut self, pack: Pack, files: &crate::diag::Files, krates: Option<&Krates>) {
        for diag in pack {
            let Some(code) = diag.code else {
                return;
            };

            // Filter out note and help severities - SARIF should only contain actionable issues
            if matches!(diag.diag.severity, Severity::Note | Severity::Help) {
                return;
            }

            let message = match &diag.extra {
                None => Message::text(diag.diag.message),
                Some(diag::Extra::Advisory(advisory)) => {
                    let mut md = String::new();

                    let meta = &advisory.metadata;

                    md.push_str("# ");
                    if let Some(url) = &meta.url {
                        write!(&mut md, "[{}]({url})", meta.id).unwrap();
                    } else {
                        md.push_str(meta.id.as_str());
                    }

                    md.push('\n');
                    md.push_str(&meta.title);
                    md.push('\n');

                    md.push_str("## Description\n");
                    md.push_str(&meta.description);
                    md.push_str("\n\n");

                    if !advisory.versions.unaffected().is_empty() {
                        md.push_str("## Unaffected\n");
                        for un in advisory.versions.unaffected() {
                            writeln!(&mut md, "- `{un}`").unwrap();
                        }
                        md.push('\n');
                    }

                    if !advisory.versions.patched().is_empty() {
                        md.push_str("## Patched\n");
                        for un in advisory.versions.patched() {
                            writeln!(&mut md, "- `{un}`").unwrap();
                        }
                        md.push('\n');
                    }

                    if let Some(affected) = &advisory.affected {
                        md.push_str("## Affected\n");
                        if !affected.functions.is_empty() {
                            md.push_str("| Functions | Versions |\n|---|---|\n");
                            for (path, reqs) in &affected.functions {
                                write!(&mut md, "|`{path}`|").unwrap();

                                for (i, req) in reqs.iter().enumerate() {
                                    if i > 0 {
                                        md.push_str(", ");
                                    }

                                    write!(&mut md, "`{req}`").unwrap();
                                }

                                md.push_str("|\n");
                            }

                            md.push('\n');
                        }

                        if !affected.arch.is_empty() {
                            md.push_str("### Arches\n");
                            for arch in &affected.arch {
                                md.push_str("- ");
                                md.push_str(arch.as_str());
                                md.push('\n');
                            }
                            md.push('\n');
                        }

                        if !affected.os.is_empty() {
                            md.push_str("### Operating Systems\n");
                            for os in &affected.os {
                                md.push_str("- ");
                                md.push_str(os.as_str());
                                md.push('\n');
                            }
                            md.push('\n');
                        }
                    }

                    Message {
                        text: meta.title.clone(),
                        markdown: Some(md),
                    }
                }
            };

            let locations: Vec<Location> = diag
                .diag
                .labels
                .iter()
                .filter_map(|label| files.sarif_location(label).ok())
                .collect();

            let krates_list: smallvec::SmallVec<[Kid; 2]> = diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect();

            let locations = if locations.is_empty() {
                // Build logical location chains from root dependencies to violating crates
                if let Some(krates_ref) = krates {
                    self.build_dependency_chain_locations(&krates_list, krates_ref)
                } else {
                    // Fallback: simple logical locations if no graph available
                    krates_list
                        .iter()
                        .map(|kid| Location {
                            physical_location: None,
                            logical_locations: vec![LogicalLocation {
                                name: kid.name().to_string(),
                                fully_qualified_name: Some(format!(
                                    "{}#{}@{}",
                                    kid.source(),
                                    kid.name(),
                                    kid.version()
                                )),
                                kind: Some("dependency".to_string()),
                                index: 0,
                                parent_index: -1,
                            }],
                        })
                        .collect::<Vec<Location>>()
                }
            } else {
                locations
            };

            // Add to diagnostics
            self.diagnostics.push(DiagnosticData {
                code,
                krates: krates_list,
                severity: diag.diag.severity,
                message,
                locations,
                extra: diag.extra,
            });

            // Add to rules if not already present
            self.rules.entry(code).or_insert(RuleData {
                code,
                severity: diag.diag.severity,
                description: code.description(),
            });
        }
    }

    pub fn generate_sarif(self) -> SarifLog {
        // Create rules from collected diagnostics
        let rules = self
            .rules
            .into_iter()
            .map(|(id, rule_data)| Rule {
                name: id.qualified_str(),
                id: id.qualified_str(),
                short_description: TextContent {
                    text: rule_data.description.to_owned(),
                },
                full_description: TextContent {
                    text: String::new(),
                },
                default_configuration: DefaultConfiguration {
                    level: severity_to_sarif_level(rule_data.severity).to_owned(),
                },
                help: Help(id),
                properties: RuleProperties {
                    tags: get_rule_tags(rule_data.code),
                    precision: "high",
                    problem_severity: severity_to_sarif_level(rule_data.severity),
                },
            })
            .collect();

        // Create results from diagnostics
        let results: Vec<SarifResult> = self
            .diagnostics
            .into_iter()
            .map(|diag| {
                let mut fingerprints = BTreeMap::new();
                let rule_id = diag.code.qualified_str();
                fingerprints.insert("cargo-deny/id".into(), rule_id.clone());

                match diag.extra {
                    Some(Extra::Advisory(advisory)) => {
                        fingerprints.insert(
                            "cargo-deny/advisory-id".into(),
                            advisory.metadata.id.to_string(),
                        );
                    }
                    None => {}
                }

                if !diag.krates.is_empty() {
                    for (i, kid) in diag.krates.into_iter().enumerate() {
                        let mut fp = String::new();

                        // Avoid including this in the fingerprint as in most projects
                        // this will be almost every crate and would just be noise
                        if !kid.source().ends_with(tame_index::CRATES_IO_INDEX) {
                            fp.push_str(kid.source());
                            fp.push('#');
                        }

                        fp.push_str(kid.name());
                        fp.push('@');
                        fp.push_str(kid.version());

                        if i > 0 {
                            fingerprints.insert(format!("cargo-deny/krate{i}"), fp);
                        } else {
                            fingerprints.insert("cargo-deny/krate".into(), fp);
                        }
                    }
                } else {
                    for (i, loc) in diag.locations.iter().enumerate() {
                        let mut fp = String::new();

                        if let Some(physical_location) = &loc.physical_location {
                            fp.push_str(&physical_location.artifact_location.uri);
                            fp.push(':');
                            write!(
                                &mut fp,
                                "{}..{}",
                                physical_location.region.byte_offset,
                                physical_location.region.byte_offset + physical_location.region.byte_length
                            )
                            .unwrap();
                        }

                        if i > 0 {
                            fingerprints.insert(format!("cargo-deny/loc{i}"), fp);
                        } else {
                            fingerprints.insert("cargo-deny/loc".into(), fp);
                        }
                    }
                }

                SarifResult {
                    rule_id,
                    message: diag.message,
                    level: severity_to_sarif_level(diag.severity),
                    locations: diag.locations,
                    partial_fingerprints: fingerprints,
                }
            })
            .collect();

        SarifLog {
            runs: vec![Run {
                tool: Tool {
                    driver: Driver {
                        rules,
                        version: None,
                    },
                },
                results,
            }],
        }
    }

    /// Builds dependency chain locations from root dependencies to violating crates
    /// Each root crate gets its own Location with:
    /// - physical_location pointing to the root crate's Cargo.toml
    /// - logical_locations chain showing the dependency path from root to violating crate
    fn build_dependency_chain_locations(
        &self,
        violating_krates: &[Kid],
        krates: &Krates,
    ) -> Vec<Location> {
        let mut locations = Vec::new();

        for kid in violating_krates {
            // Find all dependency paths from any root to this violating crate
            let paths = self.find_all_paths_to_roots(kid, krates);
            
            if paths.is_empty() {
                // Fallback: just the violating crate if we can't find any paths
                locations.push(Location {
                    physical_location: None,
                    logical_locations: vec![LogicalLocation {
                        name: kid.name().to_string(),
                        fully_qualified_name: Some(format!(
                            "{}#{}@{}",
                            kid.source(),
                            kid.name(),
                            kid.version()
                        )),
                        kind: Some("dependency".to_string()),
                        index: 0,
                        parent_index: -1,
                    }],
                });
            } else {
                // Create a Location for each unique path (each root crate)
                for path in paths {
                    // The first element in the path is the root crate
                    let root_kid = &path[0];
                    
                    // Get the root crate to access its manifest_path
                    let Some((_, root_node)) = krates.get_node(root_kid, None) else {
                        continue;
                    };
                    
                    let Node::Krate { krate: root_krate, .. } = root_node else {
                        continue;
                    };

                    // Build the logical location chain from root to violating crate
                    let mut logical_locations = Vec::new();
                    
                    for (idx, path_kid) in path.iter().enumerate() {
                        logical_locations.push(LogicalLocation {
                            name: path_kid.name().to_string(),
                            fully_qualified_name: Some(format!(
                                "{}#{}@{}",
                                path_kid.source(),
                                path_kid.name(),
                                path_kid.version()
                            )),
                            kind: Some(if idx == 0 {
                                "root-dependency".to_string()
                            } else if idx == path.len() - 1 {
                                "violating-dependency".to_string()
                            } else {
                                "transitive-dependency".to_string()
                            }),
                            index: idx as i32,
                            parent_index: if idx > 0 { (idx - 1) as i32 } else { -1 },
                        });
                    }

                    // Create Location with physical location pointing to root's Cargo.toml
                    locations.push(Location {
                        physical_location: Some(crate::sarif::model::PhysicalLocation {
                            artifact_location: crate::sarif::model::ArtifactLocation {
                                uri: format!("file://{}", root_krate.manifest_path),
                            },
                            region: crate::sarif::model::Region {
                                start_line: 1,
                                byte_offset: 0,
                                byte_length: 0,
                                snippet: None,
                                message: None,
                            },
                        }),
                        logical_locations,
                    });
                }
            }
        }

        if locations.is_empty() {
            // Final fallback
            violating_krates
                .iter()
                .map(|kid| Location {
                    physical_location: None,
                    logical_locations: vec![LogicalLocation {
                        name: kid.name().to_string(),
                        fully_qualified_name: Some(format!(
                            "{}#{}@{}",
                            kid.source(),
                            kid.name(),
                            kid.version()
                        )),
                        kind: Some("dependency".to_string()),
                        index: 0,
                        parent_index: -1,
                    }],
                })
                .collect()
        } else {
            locations
        }
    }

    /// Finds all dependency paths from any workspace member (root) to the given crate
    fn find_all_paths_to_roots(
        &self,
        target_kid: &Kid,
        krates: &Krates,
    ) -> Vec<Vec<Kid>> {
        let Some((target_node_id, _)) = krates.get_node(target_kid, None) else {
            return Vec::new();
        };

        // Get all workspace member node IDs (these are our root crates)
        let workspace_members: Vec<_> = krates.workspace_members().collect();

        let root_node_ids: HashSet<krates::NodeId> = workspace_members
            .iter()
            .filter_map(|wm| {
                if let Node::Krate { id, .. } = wm {
                    krates.nid_for_kid(id)
                } else {
                    None
                }
            })
            .collect();

        if root_node_ids.is_empty() {
            return Vec::new();
        }

        // Find all paths from target to any root by traversing backwards
        let mut all_paths = Vec::new();
        let mut current_path = Vec::new();
        let mut visited_in_path = HashSet::new();

        self.traverse_backwards_to_roots(
            target_node_id,
            &root_node_ids,
            krates,
            &mut current_path,
            &mut visited_in_path,
            &mut all_paths,
        );

        all_paths
    }

    /// Traverses backwards from a node to find all paths to any root node
    fn traverse_backwards_to_roots(
        &self,
        current: krates::NodeId,
        root_nodes: &HashSet<krates::NodeId>,
        krates: &Krates,
        current_path: &mut Vec<Kid>,
        visited_in_path: &mut HashSet<krates::NodeId>,
        all_paths: &mut Vec<Vec<Kid>>,
    ) {
        let graph = krates.graph();
        
        // If we've reached a root, save this path
        if root_nodes.contains(&current) {
            if let Node::Krate { krate, .. } = &graph[current] {
                let mut path = current_path.clone();
                path.insert(0, krate.id.clone());
                all_paths.push(path);
            }
            return;
        }

        // Prevent cycles in the current path
        if !visited_in_path.insert(current) {
            return;
        }

        // Add current node to path (we'll add it at the beginning when we build the final path)
        let current_kid = if let Node::Krate { krate, .. } = &graph[current] {
            Some(krate.id.clone())
        } else {
            None
        };

        if let Some(ref kid) = current_kid {
            current_path.push(kid.clone());
        }

        // Use direct_dependents to get crates that depend on this node
        // This automatically handles feature edges and gives us crate nodes directly
        let dependents = krates.direct_dependents(current);

        for dependent in dependents {
            // Recursively traverse from the dependent crate
            self.traverse_backwards_to_roots(
                dependent.node_id,
                root_nodes,
                krates,
                current_path,
                visited_in_path,
                all_paths,
            );
        }

        // Backtrack: remove current node from path and visited set
        current_path.pop();
        visited_in_path.remove(&current);
    }
}

#[inline]
fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error | Severity::Bug => "error",
        Severity::Warning => "warning",
        Severity::Note | Severity::Help => "note",
    }
}

#[inline]
fn get_rule_tags(code: DiagnosticCode) -> &'static [&'static str] {
    match code {
        DiagnosticCode::Advisory(_) => &["security", "vulnerability"],
        DiagnosticCode::License(_) => &["license", "compliance"],
        DiagnosticCode::Bans(_) => &["dependencies", "supply-chain"],
        DiagnosticCode::Source(_) => &["sources", "supply-chain"],
        DiagnosticCode::General(_) => &["cargo-deny"],
    }
}
