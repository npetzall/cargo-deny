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
    pub fn new(krates: Option<&'a crate::Krates>, feature_depth: Option<u32>) -> Self {
        Self {
            diagnostics: Vec::new(),
            rules: BTreeMap::new(),
            grapher: krates.map(diag::InclusionGrapher::new),
            feature_depth,
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

        let mut root_kids = HashSet::new();
        let mut locations = Vec::new();

        // Build graphs for each vulnerable crate and collect root nodes
        for graph_node in &diag.graph_nodes {
            if let Ok(graph) = grapher.build_graph(graph_node, max_feature_depth) {
                self.collect_root_kids(&graph, grapher, &mut root_kids);
            }
        }

        // Convert root crate IDs to locations
        for kid in root_kids {
            if let Some(km) = grapher
                .krates
                .krates_by_name(kid.name())
                .find(|km| km.krate.id == kid)
            {
                if let Some(loc) = self.create_manifest_location(&km.krate.manifest_path, files) {
                    locations.push(loc);
                }
            }
        }

        locations
    }

    /// Collects root crate IDs from the graph using the public API.
    fn collect_root_kids(
        &self,
        graph: &crate::diag::DependencyGraphNode,
        grapher: &diag::InclusionGrapher<'_>,
        root_kids: &mut HashSet<Kid>,
    ) {
        // Use the public method to collect root crates
        for (name, version) in graph.collect_root_crates() {
            if let Some(km) = grapher
                .krates
                .krates_by_name(&name)
                .find(|km| km.krate.version == version)
            {
                root_kids.insert(km.krate.id.clone());
            }
        }
    }

    /// Creates a SARIF location for a manifest file.
    fn create_manifest_location(
        &self,
        manifest_path: &crate::Path,
        _files: &crate::diag::Files,
    ) -> Option<Location> {
        use crate::sarif::model;

        // Create a location pointing to the beginning of the file
        // We use byte offset 0 and length 0 to point to the start
        Some(Location {
            physical_location: model::PhysicalLocation {
                artifact_location: model::ArtifactLocation {
                    uri: format!("file://{}", manifest_path),
                },
                region: model::Region {
                    start_line: 0,
                    byte_offset: 0,
                    byte_length: 0,
                    snippet: None,
                    message: None,
                },
            },
        })
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
