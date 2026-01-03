use super::{DiagnosticProcessor, DiagnosticData, create_location_from_krate};
use crate::diag::{Diag, Files};
use crate::sarif::model::Message;
use crate::sarif::locator::LocationFinder;
use codespan_reporting::diagnostic::LabelStyle;

pub struct LicenseProcessor<'a, L: LocationFinder> {
    pub grapher: &'a crate::diag::InclusionGrapher<'a>,
    pub locator: &'a L,
    pub feature_depth: u32,
}

impl<'a, L: LocationFinder> LicenseProcessor<'a, L> {
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

impl<'a, L: LocationFinder> DiagnosticProcessor for LicenseProcessor<'a, L> {
    fn process(
        &self,
        diag: Diag,
        files: &Files,
    ) -> Vec<DiagnosticData> {
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
                    locations.push(create_location_from_krate(krate));
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
                md.push_str(&crate::diag::write_compact_graph_as_text(&graph));
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
}

