use super::{DiagnosticProcessor, DiagnosticData, create_dummy_location};
use crate::diag::{Diag, Files};
use crate::sarif::model::Message;
use crate::sarif::locator::LocationFinder;
use std::fmt::Write as _;

pub struct AdvisoryProcessor<'a, L: LocationFinder> {
    pub grapher: &'a crate::diag::InclusionGrapher<'a>,
    pub locator: &'a L,
    pub feature_depth: u32,
}

impl<'a, L: LocationFinder> AdvisoryProcessor<'a, L> {
    pub fn new(
        grapher: &'a crate::diag::InclusionGrapher<'a>,
        locator: &'a L,
        feature_depth: u32,
    ) -> Self {
        Self {
            grapher,
            locator,
            feature_depth,
        }
    }

    fn max_feature_depth(&self, with_features: bool) -> usize {
        if with_features {
            self.feature_depth as usize
        } else {
            0
        }
    }
}

impl<'a, L: LocationFinder> DiagnosticProcessor for AdvisoryProcessor<'a, L> {
    fn process(
        &self,
        diag: Diag,
        files: &Files,
    ) -> Vec<DiagnosticData> {
        let code = diag.code.expect("code should be Some for Advisory");

        // Build graphs once for all graph nodes - reuse for both locations and markdown
        let max_feature_depth = self.max_feature_depth(diag.with_features);
        let mut graphs = Vec::new();
        let mut all_paths = Vec::new();

        for graph_node in &diag.graph_nodes {
            if let Ok(graph) = self.grapher.build_graph(graph_node, max_feature_depth) {
                all_paths.extend(graph.collect_project_paths());
                graphs.push(graph);
            }
        }

        let message = match &diag.extra {
            Some(crate::diag::Extra::Advisory(advisory)) => {
                let mut md = String::new();

                let meta = &advisory.metadata;

                md.push_str("# ");
                if let Some(url) = &meta.url {
                    write!(&mut md, "[{}]({url})", meta.id).unwrap();
                } else {
                    md.push_str(meta.id.as_str());
                }

                md.push_str(" - ");
                md.push_str(&meta.title);
                md.push_str("  \n\n");

                md.push_str("## Description  \n\n");
                md.push_str(&meta.description);
                md.push_str("  \n\n");

                if !advisory.versions.unaffected().is_empty() {
                    md.push_str("## Unaffected\n");
                    for un in advisory.versions.unaffected() {
                        writeln!(&mut md, "- `{un}`").unwrap();
                    }
                    md.push_str("\n\n");
                }

                if !advisory.versions.patched().is_empty() {
                    md.push_str("## Patched\n\n");
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
                    md.push_str("  \n\n## Dependency Graph  \n\n");
                    md.push_str("```  \n\n");
                    md.push_str(&crate::diag::write_compact_graph_as_text(first_graph));
                    md.push_str("  \n```  \n\n");
                }

                Message::with_markdown(meta.title.clone(), Some(md))
            }
            _ => Message::text(diag.diag.message),
        };

        // Create one diagnostic per location for advisories
        // (GitHub only uses the first location, so each location needs its own result)
        let krates: smallvec::SmallVec<[crate::Kid; 2]> = diag.graph_nodes.iter().map(|gn| gn.kid.clone()).collect();
        
        // Advisories point to Cargo.lock which is filtered out, so find root locations
        // using the dependency graph. If no locations found, create a dummy location and update message.
        let (final_locations, final_message) = {
            let locations: Vec<_> = if !all_paths.is_empty() {
                self.locator
                    .find_project_locations(&all_paths)
                    .into_iter()
                    .filter_map(|label| files.sarif_location(&label).ok())
                    .collect()
            } else {
                Vec::new()
            };
            
            if locations.is_empty() {
                let dummy_location = create_dummy_location(
                    &self.grapher.krates.workspace_root().to_string()
                );
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
            }
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
}

