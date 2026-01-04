use super::{DiagnosticProcessor, DiagnosticData};
use crate::diag::{Diag, Files};
use crate::sarif::model::Message;
use crate::sarif::locator::LocationFinder;

pub struct BanProcessor<'a, L: LocationFinder> {
    pub grapher: &'a crate::diag::InclusionGrapher<'a>,
    pub locator: &'a L,
    pub feature_depth: u32,
}

impl<'a, L: LocationFinder> BanProcessor<'a, L> {
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

    fn process_duplicate(
        &self,
        diag: Diag,
        files: &Files,
    ) -> Vec<DiagnosticData> {
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
                all_paths.extend(graph.collect_project_paths());

                // Add graph to markdown
                if !md.is_empty() {
                    md.push_str("\n\n");
                }
                md.push_str(&format!("**Dependency Graph {}**  \n\n", i + 1));
                md.push_str("```  \n");
                md.push_str(&crate::diag::write_compact_graph_as_text(&graph));
                md.push_str("  \n```  \n");
            }
        }

        let locations: Vec<_> = self.locator
            .find_project_locations(&all_paths)
            .into_iter()
            .filter_map(|label| files.sarif_location(&label).ok())
            .collect();

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
}

impl<'a, L: LocationFinder> DiagnosticProcessor for BanProcessor<'a, L> {
    fn process(
        &self,
        diag: Diag,
        files: &Files,
    ) -> Vec<DiagnosticData> {
        // Extract the inner code from diag.code
        match diag.code {
            Some(crate::diag::DiagnosticCode::Bans(crate::bans::Code::Duplicate)) => {
                self.process_duplicate(diag, files)
            }
            _ => {
                // For other ban codes, delegate to the other processor pattern
                // (process_other handles general diagnostics)
                self.process_other_ban(diag, files)
            }
        }
    }
}

impl<'a, L: LocationFinder> BanProcessor<'a, L> {
    fn process_other_ban(
        &self,
        diag: Diag,
        files: &Files,
    ) -> Vec<DiagnosticData> {
        let code = diag.code.expect("code should be Some for ban diagnostics");

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
                md.push_str(&format!("**Dependency Graph {}**  \n\n", i + 1));
                md.push_str("```  \n");
                md.push_str(&crate::diag::write_compact_graph_as_text(&graph));
                md.push_str("  \n```  \n");
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
}

