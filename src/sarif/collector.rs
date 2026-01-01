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
    grapher: diag::InclusionGrapher<'a>,
    feature_depth: u32,
    krate_spans: &'a diag::KrateSpans<'a>,
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
        krates: &'a crate::Krates,
        feature_depth: Option<u32>,
        krate_spans: &'a diag::KrateSpans<'a>,
    ) -> Self {
        Self {
            diagnostics: Vec::new(),
            rules: BTreeMap::new(),
            grapher: diag::InclusionGrapher::new(krates),
            feature_depth: feature_depth.unwrap_or(1),
            krate_spans,
        }
    }

    /// Calculates the maximum feature depth based on whether features are enabled
    fn max_feature_depth(&self, with_features: bool) -> usize {
        if with_features {
            self.feature_depth as usize
        } else {
            0
        }
    }

    /// Ensures a rule is registered for the given diagnostic code
    fn ensure_rule(&mut self, code: DiagnosticCode, severity: Severity) {
        self.rules.entry(code).or_insert_with(|| RuleData {
            code,
            severity,
            description: code.description(),
        });
    }

    pub fn add_diagnostics(&mut self, pack: Pack, files: &crate::diag::Files) {
        for diag in pack {
            // Filter out note and help severities - SARIF should only contain actionable issues
            if matches!(diag.diag.severity, Severity::Note | Severity::Help) {
                continue;
            }

            let diagnostics = match diag.code {
                None => continue,
                Some(DiagnosticCode::Advisory(_)) => {
                    self.process_advisory(diag, files)
                }
                Some(DiagnosticCode::License(_)) => {
                    self.process_license(diag, files)
                }
                Some(DiagnosticCode::Bans(code)) => {
                    self.process_ban(diag, files, code)
                }
                Some(_) => {
                    self.process_other(diag, files)
                }
            };

            // Only add rules if diagnostics were produced
            if !diagnostics.is_empty() {
                // Extract unique codes for rule registration
                let mut seen_codes = HashSet::new();
                for diag_data in &diagnostics {
                    // Use qualified_str() as a hashable key since DiagnosticCode doesn't implement Hash
                    let code_key = diag_data.code.qualified_str();
                    if seen_codes.insert(code_key) {
                        self.ensure_rule(diag_data.code, diag_data.severity);
                    }
                }

                self.diagnostics.extend(diagnostics);
            }
        }
    }

    fn process_advisory(&self, diag: crate::diag::Diag, files: &crate::diag::Files) -> Vec<DiagnosticData> {
        let code = diag.code.expect("code should be Some for Advisory");

        // Build graphs once for all graph nodes - reuse for both locations and markdown
        let max_feature_depth = self.max_feature_depth(diag.with_features);
        let mut graphs = Vec::new();
        let mut all_paths = Vec::new();

        for graph_node in &diag.graph_nodes {
            if let Ok(graph) = self.grapher.build_graph(graph_node, max_feature_depth) {
                all_paths.extend(graph.collect_root_paths());
                graphs.push(graph);
            }
        }

        // Advisories point to Cargo.lock which is filtered out, so find root locations
        // using the dependency graph.
        let locations = if !all_paths.is_empty() {
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

                // Append dependency graph using the first graph we already built
                if let Some(first_graph) = graphs.first() {
                    md.push_str("## Dependency Graph\n\n");
                    md.push_str("```\n");
                    md.push_str(&diag::write_compact_graph_as_text(first_graph));
                    md.push_str("\n```\n");
                }

                Message::with_markdown(meta.title.clone(), Some(md))
            }
            _ => Message::text(diag.diag.message),
        };

        // Create one diagnostic per location for advisories
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
        final_locations
            .into_iter()
            .map(|location| DiagnosticData {
                code,
                krates: krates.clone(),
                severity: diag.diag.severity,
                message: Message {
                    text: final_message.text.clone(),
                    markdown: final_message.markdown.clone(),
                },
                locations: vec![location],
                extra: diag.extra.clone(),
            })
            .collect()
    }

    /// Finds root workspace crates that depend on the vulnerable crate(s) by processing
    /// dependency paths collected from reverse dependency graphs.
    /// Assumes root crates are workspace members (which always have manifests).
    fn find_root_locations(
        &self,
        paths: &[diag::DependencyPath],
        files: &crate::diag::Files,
    ) -> Vec<Location> {
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
                self.krate_spans,
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

    /// Creates a location from a krate.
    /// For registry crates, uses the source to make it clear it's not a workspace crate.
    /// For local crates, uses the actual manifest path.
    fn create_location_from_krate(krate: &crate::Krate) -> Location {
        use crate::sarif::model::{ArtifactLocation, PhysicalLocation, Region};
        
        let uri = if let Some(source) = &krate.source {
            // For registry/git crates, use source to indicate it's not a workspace crate
            // Format: file://{source}#{name}@{version}
            format!("file://{}#{}@{}", source, krate.name, krate.version)
        } else {
            // For local/workspace crates, use the actual manifest path
            format!("file://{}", krate.manifest_path)
        };
        
        Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri,
                },
                region: Region {
                    start_line: 1,
                    byte_offset: 0,
                    byte_length: 0,
                    snippet: None,
                    message: Some("manifest file".to_string()),
                },
            },
        }
    }

    fn process_license(&self, diag: crate::diag::Diag, files: &crate::diag::Files) -> Vec<DiagnosticData> {
        use codespan_reporting::diagnostic::LabelStyle;

        let code = diag.code.expect("code should be Some for license diagnostics");

        // Separate primary and secondary labels
        let mut primary_labels = Vec::new();
        let mut secondary_labels = Vec::new();

        for label in &diag.diag.labels {
            match label.style {
                LabelStyle::Primary => primary_labels.push(label),
                LabelStyle::Secondary => secondary_labels.push(label),
            }
        }

        // Use only the first primary label for location (or first label if no primary)
        let location_label = primary_labels
            .first()
            .copied()
            .or_else(|| diag.diag.labels.first())
            .and_then(|label| files.sarif_location(label).ok());

        let mut locations = location_label.map(|loc| vec![loc]).unwrap_or_default();

        // If no locations found, create location from krate
        // (similar to how advisories handle missing locations)
        if locations.is_empty() {
            if let Some(first_node) = diag.graph_nodes.first() {
                // Find the krate in krates collection
                if let Some(krate) = self.grapher.krates.krates().find(|k| k.id == first_node.kid) {
                    // Create location from krate (uses source for registry crates, manifest_path for local)
                    locations.push(Self::create_location_from_krate(krate));
                }
            }
        }

        // Build markdown message
        let mut md = String::new();
        
        // Add the diagnostic message (e.g., "failed to satisfy license requirements")
        if !diag.diag.message.is_empty() {
            md.push_str(&diag.diag.message);
        }

        // Add full license expression as plain text (from first secondary label which has the full expression)
        if let Some(first_secondary) = secondary_labels.first() {
            if let Ok(secondary_loc) = files.sarif_location(first_secondary) {
                if let Some(ref snippet) = secondary_loc.physical_location.region.snippet {
                    if !md.is_empty() {
                        md.push_str("\n\n");
                    }
                    md.push_str(snippet);
                }
            }
        }

        // Add License Details with individual license names and messages
        if !primary_labels.is_empty() {
            if !md.is_empty() {
                md.push_str("\n\n");
            }
            md.push_str("**License Details:**\n");
            for label in &primary_labels {
                // Get snippet for this specific primary label (individual license name)
                let license_name = files
                    .sarif_location(label)
                    .ok()
                    .and_then(|loc| loc.physical_location.region.snippet);
                
                md.push_str("- ");
                if let Some(ref name) = license_name {
                    md.push_str(name.trim());
                }
                if !label.message.is_empty() {
                    if license_name.is_some() {
                        md.push_str(": ");
                    }
                    md.push_str(&label.message);
                }
                md.push_str("\n");
            }
        }

        // Add notes (license information)
        if !diag.diag.notes.is_empty() {
            if !md.is_empty() {
                md.push_str("\n");
            }
            md.push_str("**License Information:**\n");
            for note in &diag.diag.notes {
                // Add extra linebreak before notes that end with ":"
                if note.trim_end().ends_with(':') {
                    md.push_str("\n");
                }
                md.push_str(note);
                md.push_str("\n");
            }
            // Add extra linebreak at the end of License Information
            md.push_str("\n");
        }

        // Append dependency graph
        if let Some(first_graph_node) = diag.graph_nodes.first() {
            let max_feature_depth = self.max_feature_depth(diag.with_features);

            if let Ok(graph) = self.grapher.build_graph(first_graph_node, max_feature_depth) {
                if !md.is_empty() {
                    md.push_str("\n");
                }
                md.push_str("## Dependency Graph\n\n");
                md.push_str("```\n");
                md.push_str(&diag::write_compact_graph_as_text(&graph));
                md.push_str("\n```\n");
            }
        }

        let message = Message::with_markdown(diag.diag.message, Some(md));

        vec![DiagnosticData {
            code,
            krates: diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect(),
            severity: diag.diag.severity,
            message,
            locations,
            extra: diag.extra,
        }]
    }

    fn process_ban(&self, diag: crate::diag::Diag, files: &crate::diag::Files, code: crate::bans::Code) -> Vec<DiagnosticData> {
        match code {
            crate::bans::Code::Duplicate => {
                self.process_ban_duplicate(diag, files)
            }
            _ => {
                // For now, delegate to process_other
                self.process_other(diag, files)
            }
        }
    }

    fn process_ban_duplicate(&self, diag: crate::diag::Diag, files: &crate::diag::Files) -> Vec<DiagnosticData> {
        let code = diag.code.expect("code should be Some for duplicate diagnostics");

        let max_feature_depth = self.max_feature_depth(diag.with_features);

        // Build graphs for all graph nodes and collect root paths
        let mut all_paths = Vec::new();
        let mut md = String::new();
        
        // Add the diagnostic message
        if !diag.diag.message.is_empty() {
            md.push_str(&diag.diag.message);
        }

        // Create graphs for each graph node and add to markdown
        for (i, graph_node) in diag.graph_nodes.iter().enumerate() {
            if let Ok(graph) = self.grapher.build_graph(graph_node, max_feature_depth) {
                // Collect root paths for location finding
                all_paths.extend(graph.collect_root_paths());

                // Add graph to markdown
                if !md.is_empty() {
                    md.push_str("\n\n");
                }
                md.push_str(&format!("## Dependency Graph {}\n\n", i + 1));
                md.push_str("```\n");
                md.push_str(&diag::write_compact_graph_as_text(&graph));
                md.push_str("\n```\n");
            }
        }

        // Filter paths to only include roots that are workspace crates
        all_paths.retain(|path| path.is_workspace_member);

        // Find root locations using the filtered paths
        let locations = self.find_root_locations(&all_paths, files);

        let message = Message::with_markdown(diag.diag.message, Some(md));

        vec![DiagnosticData {
            code,
            krates: diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect(),
            severity: diag.diag.severity,
            message,
            locations,
            extra: diag.extra,
        }]
    }

    fn process_other(&self, diag: crate::diag::Diag, files: &crate::diag::Files) -> Vec<DiagnosticData> {
        let code = diag.code.expect("code should be Some for other diagnostics");

        let locations = diag
            .diag
            .labels
            .iter()
            .filter_map(|label| files.sarif_location(label).ok())
            .collect();

        let mut md = String::new();

        // Add the diagnostic message
        if !diag.diag.message.is_empty() {
            md.push_str(&diag.diag.message);
        }

        // Create graphs for each graph node and add to markdown
        let max_feature_depth = self.max_feature_depth(diag.with_features);
        for (i, graph_node) in diag.graph_nodes.iter().enumerate() {
            if let Ok(graph) = self.grapher.build_graph(graph_node, max_feature_depth) {
                // Add graph to markdown
                if !md.is_empty() {
                    md.push_str("\n\n");
                }
                md.push_str(&format!("## Dependency Graph {}\n\n", i + 1));
                md.push_str("```\n");
                md.push_str(&diag::write_compact_graph_as_text(&graph));
                md.push_str("\n```\n");
            }
        }

        let message = Message::with_markdown(diag.diag.message, Some(md));

        vec![DiagnosticData {
            code,
            krates: diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect(),
            severity: diag.diag.severity,
            message,
            locations,
            extra: diag.extra,
        }]
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
