use crate::diag::Extra;
use crate::sarif::model::{
    DefaultConfiguration, Driver, Help, Location, Message, Result as SarifResult,
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

                    // Format heading with ID and title on the same line
                    md.push_str("# ");
                    if let Some(url) = &meta.url {
                        write!(&mut md, "[{}]({url})", meta.id).unwrap();
                    } else {
                        md.push_str(meta.id.as_str());
                    }
                    md.push_str(" - ");
                    md.push_str(&meta.title);
                    md.push_str("\n\n");

                    // Description section
                    md.push_str("## Description\n\n");
                    md.push_str(&meta.description);
                    md.push_str("\n\n");

                    if !advisory.versions.unaffected().is_empty() {
                        md.push_str("## Unaffected\n\n");
                        for un in advisory.versions.unaffected() {
                            writeln!(&mut md, "- `{un}`").unwrap();
                        }
                        md.push('\n');
                    }

                    if !advisory.versions.patched().is_empty() {
                        md.push_str("## Patched\n\n");
                        for un in advisory.versions.patched() {
                            writeln!(&mut md, "- `{un}`").unwrap();
                        }
                        md.push('\n');
                    }

                    if let Some(affected) = &advisory.affected {
                        md.push_str("## Affected\n\n");
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
                            md.push_str("### Arches\n\n");
                            for arch in &affected.arch {
                                writeln!(&mut md, "- {}", arch.as_str()).unwrap();
                            }
                            md.push('\n');
                        }

                        if !affected.os.is_empty() {
                            md.push_str("### Operating Systems\n\n");
                            for os in &affected.os {
                                writeln!(&mut md, "- {}", os.as_str()).unwrap();
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
                // Find root crates that depend on the violating crates
                if let Some(krates_ref) = krates {
                    self.build_root_crate_locations(&krates_list, krates_ref)
                } else {
                    // Fallback: no locations if no graph available
                    Vec::new()
                }
            } else {
                locations
            };

            // Create one DiagnosticData per location
            if locations.is_empty() {
                // If no locations, still create one diagnostic without locations
                self.diagnostics.push(DiagnosticData {
                    code,
                    krates: krates_list,
                    severity: diag.diag.severity,
                    message,
                    locations: Vec::new(),
                    extra: diag.extra,
                });
            } else {
                // Create one DiagnosticData per location
                for location in locations {
                    self.diagnostics.push(DiagnosticData {
                        code,
                        krates: krates_list.clone(),
                        severity: diag.diag.severity,
                        message: Message {
                            text: message.text.clone(),
                            markdown: message.markdown.clone(),
                        },
                        locations: vec![location],
                        extra: diag.extra.clone(),
                    });
                }
            }

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
                let (dep_info, dep1_manifest_name, manifest_path_to_use) = if path.len() > 1 {
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
                                
                                Some((manifest_info, Some(dep_name), manifest_path))
                            })
                            .unwrap_or((None, None, root_krate.manifest_path.clone()))
                    } else {
                        (None, None, root_krate.manifest_path.clone())
                    }
                } else {
                    (None, None, root_krate.manifest_path.clone())
                };

                // Build dependency path message: root / dep1 / dep2 / ... / violating_crate
                let path_message = self.build_dependency_path_message(&path, dep1_manifest_name);

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
                            message: Some(path_message),
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

    /// Builds a dependency path message in the format: name@version / name@version / ...
    /// Uses manifest names where available (for dep1), package names otherwise
    fn build_dependency_path_message(
        &self,
        path: &[Kid],
        dep1_manifest_name: Option<&str>,
    ) -> String {
        let mut parts = Vec::new();

        for (idx, kid) in path.iter().enumerate() {
            let name = if idx == 1 {
                // Use manifest name for dep1 if available, otherwise fall back to package name
                dep1_manifest_name.unwrap_or_else(|| kid.name())
            } else {
                // Use package name for root and other dependencies
                kid.name()
            };
            let version = kid.version();
            parts.push(format!("{}@{}", name, version));
        }

        parts.join(" / ")
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
