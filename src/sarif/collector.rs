use crate::diag::Extra;
use crate::sarif::model::{
    DefaultConfiguration, Driver, Help, Location, Message, Result as SarifResult, Rule,
    RuleProperties, Run, SarifLog, TextContent, Tool,
};
use crate::{
    Kid,
    diag::{self, DiagnosticCode, Pack, Severity},
};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

/// Collects diagnostics and converts them to SARIF format
pub struct SarifCollector<'a> {
    diagnostics: Vec<DiagnosticData>,
    rules: BTreeMap<DiagnosticCode, RuleData>,
    grapher: Option<diag::InclusionGrapher<'a>>,
    feature_depth: Option<u32>,
    krate_spans: Option<&'a diag::KrateSpans<'a>>,
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

impl<'a> SarifCollector<'a> {
    pub fn new(
        krates: Option<&'a crate::Krates>,
        feature_depth: Option<u32>,
        krate_spans: Option<&'a diag::KrateSpans<'a>>,
    ) -> Self {
        Self {
            diagnostics: Vec::new(),
            rules: BTreeMap::new(),
            grapher: krates.map(diag::InclusionGrapher::new),
            feature_depth,
            krate_spans,
        }
    }
    pub fn add_diagnostics(&mut self, pack: Pack, files: &crate::diag::Files) {
        for diag in pack {
            // Filter out note and help severities - SARIF should only contain actionable issues
            if matches!(diag.diag.severity, Severity::Note | Severity::Help) {
                continue;
            }

            match diag.code {
                None => continue,
                Some(DiagnosticCode::Advisory(_)) => {
                    self.process_advisory(diag, files);
                }
                Some(_) => {
                    self.process_other(diag, files);
                }
            }
        }
    }

    fn process_advisory(&mut self, diag: crate::diag::Diag, files: &crate::diag::Files) {
        let code = diag.code.expect("code should be Some for Advisory");

        // Advisories point to Cargo.lock which is filtered out, so find root locations
        // using the dependency graph. If grapher is not available, locations will be empty.
        let locations = if let Some(grapher) = &self.grapher {
            self.find_root_locations(&diag, grapher, files)
        } else {
            Vec::new()
        };

        let message = match &diag.extra {
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
            _ => Message::text(diag.diag.message),
        };

        // Add to diagnostics
        self.diagnostics.push(DiagnosticData {
            code,
            krates: diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect(),
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

    /// Finds root workspace crates that depend on the vulnerable crate(s) by building
    /// reverse dependency graphs and collecting nodes with empty parents.
    /// Assumes root crates are workspace members (which always have manifests).
    fn find_root_locations(
        &self,
        diag: &crate::diag::Diag,
        grapher: &diag::InclusionGrapher<'_>,
        files: &crate::diag::Files,
    ) -> Vec<Location> {
        let max_feature_depth = if diag.with_features {
            self.feature_depth.map(|d| d as usize).unwrap_or(1)
        } else {
            0
        };

        let Some(krate_spans) = self.krate_spans else {
            return Vec::new();
        };

        let mut locations = Vec::new();
        // Deduplicate locations by file URI and span (byte_offset, byte_length)
        let mut seen_locations: HashSet<(String, usize, usize)> = HashSet::new();

        // Build graphs for each vulnerable crate and collect ALL paths (no deduplication)
        let mut all_paths: Vec<_> = Vec::new();

        for graph_node in &diag.graph_nodes {
            if let Ok(graph) = grapher.build_graph(graph_node, max_feature_depth) {
                // Collect all paths without deduplication
                for path in graph.collect_root_paths() {
                    all_paths.push(path);
                }
            }
        }

        // Now process each unique root with its shortest path
        // Also collect all workspace members that directly depend on the vulnerable crate
        for graph_node in &diag.graph_nodes {
            let vulnerable_kid = &graph_node.kid;
            let vulnerable_name = vulnerable_kid.name().to_string();
            let vulnerable_version_str = vulnerable_kid.version();

            // First, find all workspace members that directly depend on the vulnerable crate
            // This ensures we don't miss any workspace members, even if they're not in the paths
            if let Ok(vulnerable_version) = vulnerable_version_str.parse::<semver::Version>() {
                for workspace_member in grapher.krates.workspace_members() {
                    let krates::Node::Krate { id: member_kid, .. } = workspace_member else {
                        continue;
                    };
                    
                    // Check if this workspace member directly depends on the vulnerable crate
                    if let Some((loc, _is_workspace_dep, _dep_kid)) = self.find_dependency_location_from_path(
                        member_kid,
                        &(vulnerable_name.clone(), vulnerable_version.clone()),
                        krate_spans,
                        files,
                    ) {
                        // Deduplicate by file URI and span
                        let key = (
                            loc.physical_location.artifact_location.uri.clone(),
                            loc.physical_location.region.byte_offset,
                            loc.physical_location.region.byte_length,
                        );
                        if seen_locations.insert(key) {
                            locations.push(loc);
                        }
                    }
                }
            }

            // Process all paths (no deduplication)
            for path in &all_paths {
                // Traverse the path backwards to find the first workspace member
                // Skip if the last edge directly points to vulnerable (already handled by direct check)
                let Some(last_edge) = path.edges.last() else {
                    continue;
                };

                // Verify last edge points to vulnerable
                if last_edge.child.0 != vulnerable_name || last_edge.child.1.to_string() != vulnerable_version_str {
                    continue;
                }

                // Check if the declaring crate (parent of last edge) is a workspace member
                let declaring_crate = &last_edge.parent;
                let declaring_kid = if let Some(declaring_km) = grapher
                    .krates
                    .krates_by_name(&declaring_crate.0)
                    .find(|km| km.krate.version == declaring_crate.1)
                {
                    &declaring_km.krate.id
                } else {
                    continue;
                };

                // If declaring crate is a workspace member and directly depends on vulnerable,
                // we've already handled it in the direct check above, so skip
                let is_direct_workspace_member = grapher.krates.workspace_members().any(|wm| {
                    let krates::Node::Krate { id, .. } = wm else {
                        return false;
                    };
                    id == declaring_kid
                });

                if is_direct_workspace_member {
                    // This is a direct dependency, already handled by the direct check above
                    continue;
                }

                // Declaring crate is not a workspace member, traverse backwards to find first workspace member
                // This handles indirect dependencies (workspace member -> intermediate -> vulnerable)
                for edge in path.edges.iter().rev() {
                    let crate_in_path = &edge.parent;
                    if let Some(crate_km) = grapher
                        .krates
                        .krates_by_name(&crate_in_path.0)
                        .find(|km| km.krate.version == crate_in_path.1)
                    {
                        let crate_kid = &crate_km.krate.id;
                        
                        // Check if this crate is a workspace member
                        if grapher.krates.workspace_members().any(|wm| {
                            let krates::Node::Krate { id, .. } = wm else {
                                return false;
                            };
                            id == crate_kid
                        }) {
                            // Found a workspace member - find what it declares in this path
                            if let Some(edge) = path.edges.iter().find(|e| {
                                e.parent.0 == crate_in_path.0 && e.parent.1 == crate_in_path.1
                            }) {
                                if let Some((loc, _is_workspace_dep, _dep_kid)) = self.find_dependency_location_from_path(
                                    crate_kid,
                                    &edge.child,
                                    krate_spans,
                                    files,
                                ) {
                                    // Deduplicate by file URI and span
                                    let key = (
                                        loc.physical_location.artifact_location.uri.clone(),
                                        loc.physical_location.region.byte_offset,
                                        loc.physical_location.region.byte_length,
                                    );
                                    if seen_locations.insert(key) {
                                        locations.push(loc);
                                    }
                                }
                            }
                            break; // Found the first workspace member, stop traversing
                        }
                    }
                }
            }
        }

        locations
    }

    /// Finds the location of a dependency declaration in a root crate's manifest.
    /// If the dependency is workspace-controlled, returns the workspace location.
    /// Assumes root_kid is a workspace member (which always has a manifest).
    /// Returns (Location, is_workspace_dep, dep_kid) to allow deduplication of workspace deps.
    fn find_dependency_location_from_path(
        &self,
        root_kid: &Kid,
        dep_child: &(String, semver::Version),
        krate_spans: &diag::KrateSpans<'_>,
        files: &crate::diag::Files,
    ) -> Option<(Location, bool, Kid)> {
        use crate::diag::Label;

        // Get the manifest for the root crate (workspace members always have manifests)
        let manifest = krate_spans.manifest(root_kid)?;

        // Find the dependency in the manifest that matches the child from the path
        let manifest_dep = manifest.deps(false).find(|mdep| {
            mdep.krate.name == dep_child.0 && mdep.krate.version == dep_child.1
        })?;

        let dep_kid = manifest_dep.krate.id.clone();

        // Check if this dependency is workspace-controlled
        if manifest_dep.workspace.as_ref().map_or(false, |w| w.value) {
            // Use workspace span if available
            if let Some(ws_span) = krate_spans.workspace_span(&dep_kid) {
                if let Some(workspace_id) = krate_spans.workspace_id {
                    // Combine key and value spans to include both in the snippet
                    let combined_start = ws_span.key.start.min(ws_span.value.start);
                    let combined_end = ws_span.key.end.max(ws_span.value.end);
                    let combined_span: crate::Span = (combined_start..combined_end).into();
                    let label = Label::primary(workspace_id, combined_span);
                    return files.sarif_location(&label).ok().map(|loc| (loc, true, dep_kid));
                }
            }
        }

        // Use manifest dependency span - combine key and value spans to include both in the snippet
        let combined_start = manifest_dep.key_span.start.min(manifest_dep.value_span.start);
        let combined_end = manifest_dep.key_span.end.max(manifest_dep.value_span.end);
        let combined_span: crate::Span = (combined_start..combined_end).into();
        let label = Label::primary(manifest.id, combined_span);
        files.sarif_location(&label).ok().map(|loc| (loc, false, dep_kid))
    }

    fn process_other(&mut self, diag: crate::diag::Diag, files: &crate::diag::Files) {
        let code = diag.code.expect("code should be Some for other diagnostics");

        let locations = diag
            .diag
            .labels
            .iter()
            .filter_map(|label| files.sarif_location(label).ok())
            .collect();

        let message = Message::text(diag.diag.message);

        // Add to diagnostics
        self.diagnostics.push(DiagnosticData {
            code,
            krates: diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect(),
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

                        fp.push_str(&loc.physical_location.artifact_location.uri);
                        fp.push(':');
                        write!(
                            &mut fp,
                            "{}..{}",
                            loc.physical_location.region.byte_offset,
                            loc.physical_location.region.byte_offset
                                + loc.physical_location.region.byte_length
                        )
                        .unwrap();

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
