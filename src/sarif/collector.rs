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
            let max_feature_depth = if diag.with_features {
                self.feature_depth.map(|d| d as usize).unwrap_or(1)
            } else {
                0
            };

            // Build graphs for all graph nodes and collect root paths
            let mut all_paths = Vec::new();
            for graph_node in &diag.graph_nodes {
                if let Ok(graph) = grapher.build_graph(graph_node, max_feature_depth) {
                    all_paths.extend(graph.collect_root_paths());
                }
            }

            self.find_root_locations(&all_paths, files)
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

                // Append dependency graph if available
                if let Some(grapher) = &self.grapher {
                    if let Some(first_graph_node) = diag.graph_nodes.first() {
                        let max_feature_depth = if diag.with_features {
                            self.feature_depth.map(|d| d as usize).unwrap_or(1)
                        } else {
                            0
                        };

                        if let Ok(graph) = grapher.build_graph(first_graph_node, max_feature_depth) {
                            md.push_str("## Dependency Graph\n\n");
                            md.push_str("```\n");
                            md.push_str(&diag::write_compact_graph_as_text(&graph));
                            md.push_str("\n```\n");
                        }
                    }
                }

                Message {
                    text: meta.title.clone(),
                    markdown: Some(md),
                }
            }
            _ => Message::text(diag.diag.message),
        };

        // Add to diagnostics - create one diagnostic per location for advisories
        // (GitHub only uses the first location, so each location needs its own result)
        let krates: smallvec::SmallVec<[Kid; 2]> = diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect();
        
        // If no locations found, create a dummy location and update message
        let (final_locations, final_message) = if locations.is_empty() {
            let dummy_location = Self::create_dummy_location();
            let mut updated_message = Message {
                text: message.text.clone(),
                markdown: message.markdown.clone(),
            };
            
            // Add note about reporting to cargo-deny
            if let Some(ref mut md) = updated_message.markdown {
                md.push_str("\n\n---\n\n");
                md.push_str("**Note:** Unable to determine the location of this vulnerability in your dependency tree. ");
                md.push_str("This may indicate an issue with cargo-deny's dependency graph analysis. ");
                md.push_str("Please report this issue to [cargo-deny](https://github.com/embarkstudios/cargo-deny/issues).");
            } else {
                updated_message.markdown = Some(format!(
                    "{}\n\n---\n\n**Note:** Unable to determine the location of this vulnerability in your dependency tree. This may indicate an issue with cargo-deny's dependency graph analysis. Please report this issue to [cargo-deny](https://github.com/embarkstudios/cargo-deny/issues).",
                    updated_message.text
                ));
            }
            
            (vec![dummy_location], updated_message)
        } else {
            (locations, message)
        };
        
        // Create one diagnostic per location
        for location in final_locations {
            self.diagnostics.push(DiagnosticData {
                code,
                krates: krates.clone(),
                severity: diag.diag.severity,
                message: Message {
                    text: final_message.text.clone(),
                    markdown: final_message.markdown.clone(),
                },
                locations: vec![location],
                extra: diag.extra.clone(),
            });
        }

        // Add to rules if not already present
        self.rules.entry(code).or_insert(RuleData {
            code,
            severity: diag.diag.severity,
            description: code.description(),
        });
    }

    /// Finds root workspace crates that depend on the vulnerable crate(s) by processing
    /// dependency paths collected from reverse dependency graphs.
    /// Assumes root crates are workspace members (which always have manifests).
    fn find_root_locations(
        &self,
        paths: &[diag::DependencyPath],
        files: &crate::diag::Files,
    ) -> Vec<Location> {
        let Some(krate_spans) = self.krate_spans else {
            return Vec::new();
        };

        let mut locations = Vec::new();
        let mut seen_locations: HashSet<(String, usize, usize)> = HashSet::new();

        for path in paths {
            // path.crates[0] is the direct dependency of the root crate.
            // Skip if empty (vulnerable crate is itself a workspace member).
            let Some((dep_name, dep_version, _)) = path.crates.first() else {
                continue;
            };

            let Some(loc) = self.find_dependency_location(
                &path.root_kid,
                dep_name,
                dep_version,
                krate_spans,
                files,
            ) else {
                continue;
            };

            // Deduplicate by file URI and span
            let key = self.location_key(&loc);
            if seen_locations.insert(key) {
                locations.push(loc);
            }
        }

        locations
    }

    /// Extracts a deduplication key from a location.
    fn location_key(&self, loc: &Location) -> (String, usize, usize) {
        (
            loc.physical_location.artifact_location.uri.clone(),
            loc.physical_location.region.byte_offset,
            loc.physical_location.region.byte_length,
        )
    }

    /// Calculates a span that covers both key and value spans.
    fn merge_spans(key_span: &toml_span::Span, value_span: &toml_span::Span) -> crate::Span {
        (key_span.start.min(value_span.start)..key_span.end.max(value_span.end)).into()
    }

    /// Finds the location of a dependency declaration in a root crate's manifest.
    /// If the dependency is workspace-controlled, returns the workspace location.
    /// Assumes root_kid is a workspace member (which always has a manifest).
    fn find_dependency_location(
        &self,
        root_kid: &Kid,
        dep_name: &str,
        dep_version: &semver::Version,
        krate_spans: &diag::KrateSpans<'_>,
        files: &crate::diag::Files,
    ) -> Option<Location> {
        use crate::diag::Label;

        let manifest = krate_spans.manifest(root_kid)?;
        let manifest_dep = manifest.deps(false).find(|mdep| {
            mdep.krate.name == dep_name && mdep.krate.version == *dep_version
        })?;

        let manifest_span = Self::merge_spans(&manifest_dep.key_span, &manifest_dep.value_span);

        // If workspace-controlled, prefer workspace location; otherwise use manifest location
        let (file_id, span) = if manifest_dep.workspace.as_ref().is_some_and(|w| w.value) {
            // Try workspace location first, fall back to manifest if not available
            match (
                krate_spans.workspace_span(&manifest_dep.krate.id),
                krate_spans.workspace_id,
            ) {
                (Some(ws_span), Some(workspace_id)) => {
                    let workspace_span = Self::merge_spans(&ws_span.key, &ws_span.value);
                    (workspace_id, workspace_span)
                }
                _ => (manifest.id, manifest_span),
            }
        } else {
            (manifest.id, manifest_span)
        };

        let label = Label::primary(file_id, span);
        files.sarif_location(&label).ok()
    }

    /// Creates a dummy location for advisories when no actual location can be determined.
    /// This ensures SARIF results always have at least one location.
    fn create_dummy_location() -> Location {
        use crate::sarif::model::{ArtifactLocation, PhysicalLocation, Region};
        
        Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: "Cargo.toml".to_string(),
                },
                region: Region {
                    start_line: 1,
                    byte_offset: 0,
                    byte_length: 0,
                    snippet: None,
                    message: Some("Unable to determine dependency location".to_string()),
                },
            },
        }
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
