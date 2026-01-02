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
        (key_span.start.min(value_span.start)..key_span.end.max(value_span.end)).into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::KrateGather;

    #[test]
    fn test_merge_spans() {
        // Test merging spans where key comes before value
        let key_span = toml_span::Span { start: 10, end: 15 };
        let value_span = toml_span::Span { start: 20, end: 30 };
        let merged = Locator::merge_spans(&key_span, &value_span);
        assert_eq!(merged.start, 10);
        assert_eq!(merged.end, 30);

        // Test merging spans where value comes before key
        let key_span = toml_span::Span { start: 20, end: 25 };
        let value_span = toml_span::Span { start: 5, end: 15 };
        let merged = Locator::merge_spans(&key_span, &value_span);
        assert_eq!(merged.start, 5);
        assert_eq!(merged.end, 25);

        // Test merging overlapping spans
        let key_span = toml_span::Span { start: 10, end: 20 };
        let value_span = toml_span::Span { start: 15, end: 25 };
        let merged = Locator::merge_spans(&key_span, &value_span);
        assert_eq!(merged.start, 10);
        assert_eq!(merged.end, 25);
    }

    #[test]
    fn test_find_dependency_label() {
        // Use a real test fixture to get valid KrateSpans
        let krates = KrateGather::new("workspace").gather();
        let mut files = crate::diag::Files::new();
        let spans = crate::diag::KrateSpans::synthesize(&krates, "test", &mut files);
        let locator = Locator::new(&spans);

        // Find a root crate that has dependencies
        let root_kid = krates
            .krates()
            .find_map(|k| {
                if let Some(manifest) = spans.manifest(&k.id) {
                    if manifest.deps(false).next().is_some() {
                        Some(k.id.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .expect("test fixture should have at least one crate with dependencies");

        // Get the first dependency from the manifest
        let manifest = spans.manifest(&root_kid).unwrap();
        let first_dep = manifest
            .deps(false)
            .next()
            .expect("manifest should have at least one dependency");

        // Test finding the dependency label
        let label = locator.find_dependency_label(
            &root_kid,
            &first_dep.krate.name,
            &first_dep.krate.version,
        );

        assert!(label.is_some(), "should find label for existing dependency");
        let label = label.unwrap();
        assert_eq!(label.file_id, manifest.id);
        assert!(label.range.start <= label.range.end);
    }

    #[test]
    fn test_find_dependency_label_nonexistent() {
        let krates = KrateGather::new("workspace").gather();
        let mut files = crate::diag::Files::new();
        let spans = crate::diag::KrateSpans::synthesize(&krates, "test", &mut files);
        let locator = Locator::new(&spans);

        // Find a root crate
        let root_kid = krates
            .krates()
            .find_map(|k| {
                if spans.manifest(&k.id).is_some() {
                    Some(k.id.clone())
                } else {
                    None
                }
            })
            .expect("test fixture should have at least one crate");

        // Try to find a non-existent dependency
        let label = locator.find_dependency_label(&root_kid, "nonexistent-crate", &semver::Version::parse("999.999.999").unwrap());
        assert!(label.is_none(), "should not find label for non-existent dependency");
    }

    #[test]
    fn test_find_project_locations_empty() {
        let krates = KrateGather::new("workspace").gather();
        let mut files = crate::diag::Files::new();
        let spans = crate::diag::KrateSpans::synthesize(&krates, "test", &mut files);
        let locator = Locator::new(&spans);

        // Test with empty paths
        let paths = vec![];
        let locations = locator.find_project_locations(&paths);
        assert!(locations.is_empty());
    }

    #[test]
    fn test_find_project_locations_with_empty_crates() {
        let krates = KrateGather::new("workspace").gather();
        let mut files = crate::diag::Files::new();
        let spans = crate::diag::KrateSpans::synthesize(&krates, "test", &mut files);
        let locator = Locator::new(&spans);

        // Create a path with empty crates (vulnerable crate is itself a workspace member)
        let root_kid = krates
            .krates()
            .next()
            .map(|k| k.id.clone())
            .expect("test fixture should have at least one crate");

        let path = diag::DependencyPath {
            root: ("test".to_string(), semver::Version::parse("1.0.0").unwrap()),
            root_kid: root_kid.clone(),
            crates: vec![], // Empty crates means vulnerable crate is workspace member
            is_project_crate: true,
        };

        let locations = locator.find_project_locations(&[path]);
        // Should skip paths with empty crates
        assert!(locations.is_empty());
    }

    #[test]
    fn test_find_project_locations_deduplication() {
        let krates = KrateGather::new("workspace").gather();
        let mut files = crate::diag::Files::new();
        let spans = crate::diag::KrateSpans::synthesize(&krates, "test", &mut files);
        let locator = Locator::new(&spans);

        // Find a root crate with dependencies
        let (root_kid, dep_name, dep_version, dep_kid) = krates
            .krates()
            .find_map(|k| {
                if let Some(manifest) = spans.manifest(&k.id) {
                    manifest.deps(false).next().map(|dep| {
                        (
                            k.id.clone(),
                            dep.krate.name.clone(),
                            dep.krate.version.clone(),
                            dep.krate.id.clone(),
                        )
                    })
                } else {
                    None
                }
            })
            .expect("test fixture should have at least one crate with dependencies");

        // Create multiple paths pointing to the same dependency
        let path1 = diag::DependencyPath {
            root: ("test1".to_string(), semver::Version::parse("1.0.0").unwrap()),
            root_kid: root_kid.clone(),
            crates: vec![(dep_name.clone(), dep_version.clone(), dep_kid.clone())],
            is_project_crate: false,
        };

        let path2 = diag::DependencyPath {
            root: ("test2".to_string(), semver::Version::parse("1.0.0").unwrap()),
            root_kid: root_kid.clone(),
            crates: vec![(dep_name.clone(), dep_version.clone(), dep_kid.clone())],
            is_project_crate: false,
        };

        let locations = locator.find_project_locations(&[path1, path2]);
        // Should deduplicate and return only one location
        assert_eq!(locations.len(), 1);
    }

    #[test]
    fn test_label_hash_ordering() {
        let label1 = diag::Label::primary(1, 10..20);
        let label2 = diag::Label::primary(1, 15..25);
        let label3 = diag::Label::primary(2, 10..20);

        let hash1 = LabelHash::new(label1);
        let hash2 = LabelHash::new(label2);
        let hash3 = LabelHash::new(label3);

        // Test ordering by file_id first
        assert!(hash1 < hash3);
        assert!(hash3 > hash1);

        // Test ordering by range start when file_id is same
        assert!(hash1 < hash2);
        assert!(hash2 > hash1);

        // Test equality - create a new label with the same values
        let label1_dup = diag::Label::primary(1, 10..20);
        let hash1_dup = LabelHash::new(label1_dup);
        assert_eq!(hash1, hash1_dup);
    }
}

