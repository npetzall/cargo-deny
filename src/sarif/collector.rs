use crate::diag::Extra;
use crate::sarif::advisory;
use crate::sarif::model::{
    DefaultConfiguration, Driver, Help, Location, Message, Result as SarifResult,
    Rule, RuleProperties, Run, SarifLog, TextContent, Tool,
};
use crate::{
    Kid, Krates,
    diag::{self, DiagnosticCode, InclusionGrapher, Pack, Severity, write_graph_as_text},
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
            // Filter out note and help severities - SARIF should only contain actionable issues
            if matches!(diag.diag.severity, Severity::Note | Severity::Help) {
                continue;
            }

            let severity = diag.diag.severity;
            let (diagnostics, code) = match diag.code {
                None => continue,
                Some(code @ DiagnosticCode::Advisory(_)) => {
                    (self.add_advisory(diag, code, files, krates), code)
                }
                Some(code @ DiagnosticCode::License(_)) => {
                    (self.add_license(diag, code, files, krates), code)
                }
                Some(code) => {
                    (self.add_other(diag, code, files, krates), code)
                }
            };

            if !diagnostics.is_empty() {
                self.diagnostics.extend(diagnostics);
                self.add_rule_if_needed(code, severity);
            }
        }
    }

    /// Handles processing of advisory diagnostics, returning diagnostic data
    fn add_advisory(
        &self,
        diag: diag::Diag,
        code: DiagnosticCode,
        files: &crate::diag::Files,
        krates: Option<&Krates>,
    ) -> Vec<DiagnosticData> {
        let krates_list: smallvec::SmallVec<[Kid; 2]> = 
            diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect();

        let (mut message, locations) = if let Some(diag::Extra::Advisory(advisory)) = &diag.extra {
            advisory::process_advisory(
                advisory,
                &krates_list,
                krates,
                |krates_list, krates_ref| self.build_root_crate_locations(krates_list, krates_ref),
            )
        } else {
            // Fallback for non-advisory (shouldn't happen in this function)
            (Message::text(diag.diag.message.clone()), self.extract_locations(&diag, files))
        };

        // Add dependency tree to message if available
        message = self.add_dependency_tree_to_message(message, &diag.graph_nodes, krates, diag.with_features);

        self.create_diagnostic_data(code, diag.diag.severity, message, locations, krates_list, diag.extra)
    }

    /// Handles processing of license diagnostics, returning diagnostic data
    fn add_license(
        &self,
        diag: diag::Diag,
        code: DiagnosticCode,
        files: &crate::diag::Files,
        krates: Option<&Krates>,
    ) -> Vec<DiagnosticData> {
        let krates_list: smallvec::SmallVec<[Kid; 2]> = 
            diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect();

        // Group labels by physical location and build enhanced message
        let (location, mut message) = self.process_license_diagnostic(&diag, files);

        // Add dependency tree to message if available
        message = self.add_dependency_tree_to_message(message, &diag.graph_nodes, krates, diag.with_features);

        // If no location from labels, fall back to building root crate locations (for Unlicensed, NoLicenseField, etc.)
        let locations = if let Some(loc) = location {
            vec![loc]
        } else {
            // Fall back to root crate locations if we have krates information
            if let Some(krates_ref) = krates {
                self.build_root_crate_locations(&krates_list, krates_ref)
            } else {
                Vec::new()
            }
        };

        // Create diagnostic data with location in a Vec (1:1 relationship)
        vec![DiagnosticData {
            code,
            krates: krates_list,
            severity: diag.diag.severity,
            message,
            locations,
            extra: diag.extra,
        }]
    }

    /// Processes license diagnostics by combining label messages
    /// All labels for a license diagnostic point to the same file, so we just collect all messages
    fn process_license_diagnostic(
        &self,
        diag: &diag::Diag,
        files: &crate::diag::Files,
    ) -> (Option<Location>, Message) {
        // Collect label info (message and license name from snippet) and find the first valid location
        struct LabelInfo {
            license_name: Option<String>,
            message: String,
        }
        
        let mut label_infos = Vec::new();
        let mut first_location: Option<Location> = None;

        for label in &diag.diag.labels {
            let Ok(location) = files.sarif_location(label) else {
                continue;
            };
            
            // Extract license name from snippet before moving location
            let license_name = location
                .physical_location
                .as_ref()
                .and_then(|pl| pl.region.snippet.as_ref())
                .map(|s| s.trim().to_string());
            
            // Store the first valid location
            if first_location.is_none() {
                first_location = Some(location);
            }
            
            if !label.message.is_empty() {
                label_infos.push(LabelInfo {
                    license_name,
                    message: label.message.clone(),
                });
            }
        }

        // Build enhanced message with all label details and notes
        let base_message = diag.diag.message.clone();
        let mut md = String::new();
        md.push_str(&base_message);
        
        // Add details section if we have label messages
        if !label_infos.is_empty() {
            md.push_str("\n\n## Details\n\n");
            
            // Add the full license expression snippet from the first location
            if let Some(ref location) = first_location {
                if let Some(ref physical_location) = location.physical_location {
                    if let Some(ref snippet) = physical_location.region.snippet {
                        md.push_str(&format!("**Location:** `{}`\n\n", snippet.trim()));
                    }
                }
            }
            
            // Add all label messages as bullet points with license names in code blocks
            for info in &label_infos {
                if let Some(ref license_name) = info.license_name {
                    md.push_str(&format!("- `{}`: {}\n", license_name, info.message));
                } else {
                    md.push_str(&format!("- {}\n", info.message));
                }
            }
            md.push('\n');
        }
        
        // Add notes section if available (license details, etc.)
        if !diag.diag.notes.is_empty() {
            md.push_str("## License Information\n\n");
            
            // Parse notes to create one list per license
            // Notes format: "MIT - MIT License:" followed by indented items like "  - OSI approved"
            let mut current_license: Option<String> = None;
            let mut current_items: Vec<String> = Vec::new();
            
            for note in &diag.diag.notes {
                let trimmed = note.trim();
                
                // Check if this is a license header (ends with ":" and doesn't start with "  -")
                if trimmed.ends_with(':') && !trimmed.starts_with("  -") {
                    // Output previous license's list if we have one
                    if let Some(ref license) = current_license {
                        md.push_str(&format!("**{}**\n\n", license));
                        for item in &current_items {
                            md.push_str(&format!("- {}\n", item));
                        }
                        md.push('\n');
                    }
                    // Start new license
                    current_license = Some(trimmed.trim_end_matches(':').to_string());
                    current_items.clear();
                } else if trimmed.starts_with("  -") {
                    // This is an item for the current license
                    let item = trimmed.trim_start_matches("  -").trim();
                    current_items.push(item.to_string());
                } else if !trimmed.is_empty() {
                    // Standalone note (not part of a license block)
                    if current_license.is_none() {
                        md.push_str(&format!("- {}\n", trimmed));
                    } else {
                        current_items.push(trimmed.to_string());
                    }
                }
            }
            
            // Output the last license's list if we have one
            if let Some(ref license) = current_license {
                md.push_str(&format!("**{}**\n\n", license));
                for item in &current_items {
                    md.push_str(&format!("- {}\n", item));
                }
            }
        }
        
        let message = Message {
            text: base_message,
            markdown: Some(md),
        };

        // Return the first location (all labels point to the same file)
        (first_location, message)
    }

    /// Handles processing of other diagnostic types (Bans, Sources, General, etc.), returning diagnostic data
    fn add_other(
        &self,
        diag: diag::Diag,
        code: DiagnosticCode,
        files: &crate::diag::Files,
        krates: Option<&Krates>,
    ) -> Vec<DiagnosticData> {
        let mut message = Message::text(diag.diag.message.clone());
        let initial_locations = self.extract_locations(&diag, files);
        let krates_list: smallvec::SmallVec<[Kid; 2]> = 
            diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect();

        let locations = self.handle_default_locations(initial_locations, &krates_list, krates);

        // Add dependency tree to message if available
        message = self.add_dependency_tree_to_message(message, &diag.graph_nodes, krates, diag.with_features);

        self.create_diagnostic_data(code, diag.diag.severity, message, locations, krates_list, diag.extra)
    }

    /// Extracts locations from diagnostic labels
    fn extract_locations(&self, diag: &diag::Diag, files: &crate::diag::Files) -> Vec<Location> {
        diag.diag
            .labels
            .iter()
            .filter_map(|label| files.sarif_location(label).ok())
            .collect()
    }

    /// Handles location resolution for other diagnostic types (Bans, Sources, etc.)
    /// These should have locations from Cargo.toml, but fallback if needed
    fn handle_default_locations(
        &self,
        initial_locations: Vec<Location>,
        krates_list: &[Kid],
        krates: Option<&Krates>,
    ) -> Vec<Location> {
        if initial_locations.is_empty() {
            if let Some(krates_ref) = krates {
                self.build_root_crate_locations(krates_list, krates_ref)
            } else {
                Vec::new()
            }
        } else {
            initial_locations
        }
    }

    /// Adds dependency tree information to the message markdown if graph nodes and krates are available
    fn add_dependency_tree_to_message(
        &self,
        message: Message,
        graph_nodes: &[diag::GraphNode],
        krates: Option<&Krates>,
        with_features: bool,
    ) -> Message {
        // Only add tree if we have graph nodes and krates
        if graph_nodes.is_empty() || krates.is_none() {
            return message;
        }

        let krates_ref = krates.unwrap();
        let grapher = InclusionGrapher::new(krates_ref);
        let max_feature_depth = if with_features { usize::MAX } else { 0 };

        let mut trees = Vec::new();
        for gn in graph_nodes {
            if let Ok(graph) = grapher.build_graph(gn, max_feature_depth) {
                let tree_text = write_graph_as_text(&graph);
                if !tree_text.trim().is_empty() {
                    trees.push(tree_text);
                }
            }
        }

        // If we have trees, add them to the markdown
        if !trees.is_empty() {
            let mut md = message.markdown.unwrap_or_else(|| {
                // If no markdown exists, create it from the text
                message.text.clone()
            });

            md.push_str("\n\n## Dependency Tree\n\n");
            for (i, tree) in trees.iter().enumerate() {
                if trees.len() > 1 {
                    md.push_str(&format!("### Crate {}\n\n", i + 1));
                }
                md.push_str("```\n");
                md.push_str(tree);
                md.push_str("```\n\n");
            }

            Message {
                text: message.text,
                markdown: Some(md),
            }
        } else {
            message
        }
    }

    /// Creates diagnostic data entries, returning them as a vector
    fn create_diagnostic_data(
        &self,
        code: DiagnosticCode,
        severity: Severity,
        message: Message,
        locations: Vec<Location>,
        krates_list: smallvec::SmallVec<[Kid; 2]>,
        extra: Option<diag::Extra>,
    ) -> Vec<DiagnosticData> {
        if locations.is_empty() {
            // If no locations, still create one diagnostic without locations
            vec![DiagnosticData {
                code,
                krates: krates_list,
                severity,
                message,
                locations: Vec::new(),
                extra,
            }]
        } else {
            // Create one DiagnosticData per location
            locations
                .into_iter()
                .map(|location| DiagnosticData {
                    code,
                    krates: krates_list.clone(),
                    severity,
                    message: Message {
                        text: message.text.clone(),
                        markdown: message.markdown.clone(),
                    },
                    locations: vec![location],
                    extra: extra.clone(),
                })
                .collect()
        }
    }

    /// Adds a rule to the rules map if it doesn't already exist
    fn add_rule_if_needed(&mut self, code: DiagnosticCode, severity: Severity) {
        self.rules.entry(code).or_insert(RuleData {
            code,
            severity,
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

    /// Builds locations pointing to root crates that depend on the violating crates
    /// Each root crate gets its own Location with physical_location pointing to the root crate's Cargo.toml
    /// If a dependency uses `workspace = true`, the location points to the workspace manifest instead
    fn build_root_crate_locations(
        &self,
        violating_krates: &[Kid],
        krates: &Krates,
    ) -> Vec<Location> {
        let mut locations = Vec::new();
        let mut seen_roots = HashSet::new();
        // Deduplicate by physical location URI + region
        let mut seen_locations = HashSet::new();

        for kid in violating_krates {
            // Find all dependency paths from any root to this violating crate
            let paths = self.find_all_paths_to_roots(kid, krates);
            
            // Create a Location for each unique root crate
            for path in paths {
                // The first element in the path is the root crate
                let root_kid = &path[0];
                
                // Skip if we've already seen this root
                if !seen_roots.insert(root_kid.clone()) {
                    continue;
                }
                
                // Get the root crate to access its manifest_path
                let Some((_, root_node)) = krates.get_node(root_kid, None) else {
                    continue;
                };
                
                let Node::Krate { krate: root_krate, .. } = root_node else {
                    continue;
                };

                // The path is already in correct order: [root, dep1, dep2, ..., violating_crate]
                // Find dep1 (the first dependency in the path) in the root crate's manifest
                // Only check dep1 - if it's not directly declared in root, we can't find it
                let (dep_info, manifest_path_to_use) = if path.len() > 1 {
                    let dep1_kid = &path[1];
                    if let Some(root_nid) = krates.nid_for_kid(root_kid) {
                        // Check if dep1 is directly declared in the root crate
                        root_krate
                            .deps
                            .iter()
                            .enumerate()
                            .find_map(|(i, dep)| {
                                krates
                                    .resolved_dependency(root_nid, i)
                                    .filter(|resolved_kid| resolved_kid.id == *dep1_kid)
                                    .map(|_| dep.name.as_str())
                            })
                            .and_then(|dep_name| {
                                // Check if this dependency uses workspace = true
                                let is_workspace_dep = self.check_if_workspace_dependency(
                                    root_krate.manifest_path.as_std_path(),
                                    dep_name,
                                );
                                
                                let (manifest_info, manifest_path) = if is_workspace_dep {
                                    // Look in workspace manifest
                                    let workspace_manifest = krates.workspace_root().join("Cargo.toml");
                                    let info = self.find_workspace_dependency_in_manifest(
                                        workspace_manifest.as_std_path(),
                                        dep_name,
                                    );
                                    (info, workspace_manifest)
                                } else {
                                    // Look in root crate manifest
                                    let info = self.find_dependency_in_manifest(
                                        root_krate.manifest_path.as_std_path(),
                                        dep_name,
                                    );
                                    (info, root_krate.manifest_path.clone())
                                };
                                
                                Some((manifest_info, manifest_path))
                            })
                            .unwrap_or((None, root_krate.manifest_path.clone()))
                    } else {
                        (None, root_krate.manifest_path.clone())
                    }
                } else {
                    (None, root_krate.manifest_path.clone())
                };

                // Create Location with physical location pointing to root's Cargo.toml or workspace manifest
                let (start_line, snippet, byte_offset, byte_length) = dep_info
                    .map(|(line, snip, offset, length)| (line, Some(snip), offset, length))
                    .unwrap_or((1, None, 0, 0));

                // Create location key for deduplication (URI + region)
                let location_key = format!(
                    "{}:{}:{}:{}",
                    manifest_path_to_use,
                    start_line,
                    byte_offset,
                    byte_length
                );

                // Skip if we've already created a location for this exact position
                if !seen_locations.insert(location_key) {
                    continue;
                }

                locations.push(Location {
                    physical_location: Some(crate::sarif::model::PhysicalLocation {
                        artifact_location: crate::sarif::model::ArtifactLocation {
                            uri: format!("file://{}", manifest_path_to_use),
                        },
                        region: crate::sarif::model::Region {
                            start_line,
                            byte_offset,
                            byte_length,
                            snippet,
                            message: None,
                        },
                    }),
                });
            }
        }

        locations
    }

    /// Finds the dependency declaration in a Cargo.toml manifest
    /// Returns (line_number, line_content, byte_offset, byte_length) if found, None otherwise
    /// If the dependency appears in multiple sections, prioritizes [dependencies] > [dev-dependencies] > [build-dependencies]
    fn find_dependency_in_manifest(
        &self,
        manifest_path: &std::path::Path,
        dep_name_in_manifest: &str,
    ) -> Option<(usize, String, usize, usize)> {
        // Read the manifest file
        let contents = std::fs::read_to_string(manifest_path).ok()?;
        
        // Parse the TOML file
        let root = toml_span::parse(&contents).ok()?;

        // Helper to find dependency in a specific section
        // Returns (priority, key_span, value_span) if found
        // Priority: dependencies (0) > dev-dependencies (1) > build-dependencies (2)
        let find_in_section = |pointer: &str, priority: usize| -> Option<(usize, toml_span::Span, toml_span::Span)> {
            let dep_table = root.pointer(pointer)?;
            let table = dep_table.as_table()?;
            let (key, dep_value) = table.get_key_value(dep_name_in_manifest)?;
            Some((priority, key.span, dep_value.span))
        };

        // Check sections in priority order: dependencies > dev-dependencies > build-dependencies
        let mut best_match: Option<(usize, toml_span::Span, toml_span::Span)> = None;

        // Check [dependencies] section (priority 0)
        if let Some(match_info) = find_in_section("/dependencies", 0) {
            best_match = Some(match_info);
        }

        // Check [dev-dependencies] section (priority 1)
        if let Some(match_info) = find_in_section("/dev-dependencies", 1) {
            match best_match {
                None => best_match = Some(match_info),
                Some((best_priority, _, _)) if match_info.0 < best_priority => {
                    best_match = Some(match_info);
                }
                _ => {}
            }
        }

        // Check [build-dependencies] section (priority 2)
        if let Some(match_info) = find_in_section("/build-dependencies", 2) {
            match best_match {
                None => best_match = Some(match_info),
                Some((best_priority, _, _)) if match_info.0 < best_priority => {
                    best_match = Some(match_info);
                }
                _ => {}
            }
        }

        // Check target-specific dependency sections (treated as regular dependencies, priority 0)
        if let Some(targets) = root.pointer("/target") {
            if let Some(targets_table) = targets.as_table() {
                for (_target_key, target_value) in targets_table.iter() {
                    if let Some(target_table) = target_value.as_table() {
                        // Check [target.*.dependencies]
                        if let Some(deps_table) = target_table.get("dependencies") {
                            if let Some(deps_table) = deps_table.as_table() {
                                if let Some((key, dep_value)) = deps_table.get_key_value(dep_name_in_manifest) {
                                    match best_match {
                                        None => {
                                            best_match = Some((0, key.span, dep_value.span));
                                        }
                                        Some((best_priority, _, _)) if best_priority > 0 => {
                                            best_match = Some((0, key.span, dep_value.span));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        // Check [target.*.dev-dependencies]
                        if let Some(deps_table) = target_table.get("dev-dependencies") {
                            if let Some(deps_table) = deps_table.as_table() {
                                if let Some((key, dep_value)) = deps_table.get_key_value(dep_name_in_manifest) {
                                    match best_match {
                                        None => {
                                            best_match = Some((1, key.span, dep_value.span));
                                        }
                                        Some((best_priority, _, _)) if best_priority > 1 => {
                                            best_match = Some((1, key.span, dep_value.span));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        // Check [target.*.build-dependencies]
                        if let Some(deps_table) = target_table.get("build-dependencies") {
                            if let Some(deps_table) = deps_table.as_table() {
                                if let Some((key, dep_value)) = deps_table.get_key_value(dep_name_in_manifest) {
                                    match best_match {
                                        None => {
                                            best_match = Some((2, key.span, dep_value.span));
                                        }
                                        Some((best_priority, _, _)) if best_priority > 2 => {
                                            best_match = Some((2, key.span, dep_value.span));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Extract information from the best match
        let (_, key_span, value_span) = best_match?;

        // Use the key span for byte offset (start of the dependency name)
        // Use the value span end for the full dependency declaration length
        let byte_offset = key_span.start;
        let byte_length = value_span.end - key_span.start;

        // Calculate line number from byte offset
        let line_number = contents[..byte_offset.min(contents.len())]
            .chars()
            .filter(|&c| c == '\n')
            .count()
            + 1;

        // Extract the line content (from key start to end of line containing value end)
        let line_end = contents[byte_offset..]
            .find('\n')
            .map(|pos| byte_offset + pos + 1)
            .unwrap_or(contents.len());
        let line_start = contents[..byte_offset]
            .rfind('\n')
            .map(|pos| pos + 1)
            .unwrap_or(0);
        let line_content = contents[line_start..line_end.min(contents.len())]
            .trim_end()
            .to_string();

        Some((line_number, line_content, byte_offset, byte_length))
    }

    /// Checks if a dependency declaration uses `workspace = true`
    fn check_if_workspace_dependency(
        &self,
        manifest_path: &std::path::Path,
        dep_name: &str,
    ) -> bool {
        let contents = match std::fs::read_to_string(manifest_path) {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        let root = match toml_span::parse(&contents) {
            Ok(r) => r,
            Err(_) => return false,
        };
        
        // Check all dependency sections for this dependency
        let sections = [
            "/dependencies",
            "/dev-dependencies",
            "/build-dependencies",
        ];
        
        for section in sections {
            if let Some(dep_table) = root.pointer(section) {
                if let Some(table) = dep_table.as_table() {
                    if let Some((_, dep_value)) = table.get_key_value(dep_name) {
                        // Check if it's a table with workspace = true
                        if let Some(dep_table) = dep_value.as_table() {
                            if let Some(workspace_val) = dep_table.get("workspace") {
                                if let Some(true) = workspace_val.as_bool() {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Also check target-specific sections
        if let Some(targets) = root.pointer("/target") {
            if let Some(targets_table) = targets.as_table() {
                for (_target_key, target_value) in targets_table.iter() {
                    if let Some(target_table) = target_value.as_table() {
                        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                            if let Some(deps_table) = target_table.get(section) {
                                if let Some(deps_table) = deps_table.as_table() {
                                    if let Some((_, dep_value)) = deps_table.get_key_value(dep_name) {
                                        if let Some(dep_table) = dep_value.as_table() {
                                            if let Some(workspace_val) = dep_table.get("workspace") {
                                                if let Some(true) = workspace_val.as_bool() {
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        false
    }

    /// Finds a dependency in the [workspace.dependencies] section
    fn find_workspace_dependency_in_manifest(
        &self,
        manifest_path: &std::path::Path,
        dep_name: &str,
    ) -> Option<(usize, String, usize, usize)> {
        let contents = std::fs::read_to_string(manifest_path).ok()?;
        let root = toml_span::parse(&contents).ok()?;
        
        // Look in [workspace.dependencies]
        let workspace_deps = root.pointer("/workspace/dependencies")?;
        let table = workspace_deps.as_table()?;
        let (key, dep_value) = table.get_key_value(dep_name)?;
        
        let key_span = key.span;
        let value_span = dep_value.span;
        
        let byte_offset = key_span.start;
        let byte_length = value_span.end - key_span.start;
        
        let line_number = contents[..byte_offset.min(contents.len())]
            .chars()
            .filter(|&c| c == '\n')
            .count()
            + 1;
        
        let line_end = contents[byte_offset..]
            .find('\n')
            .map(|pos| byte_offset + pos + 1)
            .unwrap_or(contents.len());
        let line_start = contents[..byte_offset]
            .rfind('\n')
            .map(|pos| pos + 1)
            .unwrap_or(0);
        let line_content = contents[line_start..line_end.min(contents.len())]
            .trim_end()
            .to_string();
        
        Some((line_number, line_content, byte_offset, byte_length))
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
                // Reverse dependencies (everything after root) to get correct order: [root, dep1, dep2, ..., violating]
                // This is more efficient than prepending during traversal
                if path.len() > 1 {
                    path[1..].reverse();
                }
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
