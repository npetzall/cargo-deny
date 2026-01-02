use crate::{
    Kid,
    diag::{self, Label},
};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
struct LabelHash {
    label: Label,
}

impl LabelHash {
    fn new(label: Label) -> Self {
        Self { label }
    }

    fn into_label(self) -> Label {
        self.label
    }
}

impl PartialEq for LabelHash {
    fn eq(&self, other: &Self) -> bool {
        self.label.file_id == other.label.file_id
            && self.label.range.start == other.label.range.start
            && self.label.range.end == other.label.range.end
    }
}

impl Eq for LabelHash {}

impl PartialOrd for LabelHash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LabelHash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.label.file_id
            .cmp(&other.label.file_id)
            .then_with(|| self.label.range.start.cmp(&other.label.range.start))
            .then_with(|| self.label.range.end.cmp(&other.label.range.end))
    }
}

/// Trait for finding dependency locations in manifests for SARIF results
pub trait LocationFinder {
    /// Finds project locations for the given dependency paths.
    ///
    /// Returns a deduplicated list of labels where dependencies are declared
    /// in the project's manifest files.
    fn find_project_locations(
        &self,
        paths: &[diag::DependencyPath],
    ) -> Vec<Label>;
}

/// Finds dependency locations in manifests for SARIF results
pub struct Locator<'a> {
    krate_spans: &'a diag::KrateSpans<'a>,
}

impl<'a> Locator<'a> {
    pub fn new(krate_spans: &'a diag::KrateSpans<'a>) -> Self {
        Self { krate_spans }
    }

    fn find_dependency_label(
        &self,
        root_kid: &Kid,
        dep_name: &str,
        dep_version: &semver::Version,
    ) -> Option<Label> {
        let manifest = self.krate_spans.manifest(root_kid)?;
        let manifest_dep = manifest.deps(false).find(|mdep| {
            mdep.krate.name == dep_name && mdep.krate.version == *dep_version
        })?;

        let manifest_span = Self::merge_spans(&manifest_dep.key_span, &manifest_dep.value_span);

        // If workspace-controlled, prefer workspace location; otherwise use manifest location
        let (file_id, span) = if manifest_dep.workspace.as_ref().is_some_and(|w| w.value) {
            // Try workspace location first, fall back to manifest if not available
            match (
                self.krate_spans.workspace_span(&manifest_dep.krate.id),
                self.krate_spans.workspace_id,
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

        Some(Label::primary(file_id, span))
    }

    /// Calculates a span that covers both key and value spans.
    fn merge_spans(key_span: &toml_span::Span, value_span: &toml_span::Span) -> crate::Span {
        (key_span.start.min(value_span.start)..value_span.end.max(value_span.end)).into()
    }
}

impl<'a> LocationFinder for Locator<'a> {
    fn find_project_locations(
        &self,
        paths: &[diag::DependencyPath],
    ) -> Vec<Label> {
        let mut seen: BTreeSet<LabelHash> = BTreeSet::new();

        for path in paths {
            // path.crates[0] is the direct dependency of the root crate.
            // Skip if empty (vulnerable crate is itself a workspace member).
            let Some((dep_name, dep_version, _)) = path.crates.first() else {
                continue;
            };

            if let Some(label) = self.find_dependency_label(
                &path.root_kid,
                dep_name,
                dep_version,
            ) {
                seen.insert(LabelHash::new(label));
            }
        }

        seen.into_iter().map(|key| key.into_label()).collect()
    }
}

