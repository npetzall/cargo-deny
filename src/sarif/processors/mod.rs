pub mod advisory;
pub mod license;
pub mod ban;
pub mod other;

use crate::diag::{Diag, Files};
use crate::sarif::model::Location;
use crate::{Kid, Krate};
use crate::diag::DiagnosticCode;
use crate::sarif::model::Message;
use crate::diag::Severity;

use super::locator::LocationFinder;

/// The trait that all processors implement
pub trait DiagnosticProcessor {
    fn process(
        &self,
        diag: Diag,
        files: &Files,
    ) -> Vec<DiagnosticData>;
}

/// Internal type used by processors and collector
pub struct DiagnosticData {
    pub code: DiagnosticCode,
    pub severity: Severity,
    pub krates: smallvec::SmallVec<[Kid; 2]>,
    pub message: Message,
    pub locations: Vec<Location>,
    pub extra: Option<crate::diag::Extra>,
}

/// Enum wrapper for processors
pub enum Processor<'a, L: LocationFinder> {
    Advisory(advisory::AdvisoryProcessor<'a, L>),
    License(license::LicenseProcessor<'a, L>),
    Ban(ban::BanProcessor<'a, L>),
    Source(other::OtherProcessor<'a, L>),
    Other(other::OtherProcessor<'a, L>),
}

/// Set of all processors, organized by diagnostic variant
pub struct ProcessorSet<'a, L: LocationFinder> {
    advisory: Processor<'a, L>,
    license: Processor<'a, L>,
    ban: Processor<'a, L>,
    source: Processor<'a, L>,
    other: Processor<'a, L>,
}

impl<'a, L: LocationFinder> DiagnosticProcessor for Processor<'a, L> {
    fn process(
        &self,
        diag: Diag,
        files: &Files,
    ) -> Vec<DiagnosticData> {
        match self {
            Processor::Advisory(p) => p.process(diag, files),
            Processor::License(p) => p.process(diag, files),
            Processor::Ban(p) => p.process(diag, files),
            Processor::Source(p) => p.process(diag, files),
            Processor::Other(p) => p.process(diag, files),
        }
    }
}

impl<'a, L: LocationFinder> ProcessorSet<'a, L> {
    pub fn new(
        grapher: &'a crate::diag::InclusionGrapher<'a>,
        locator: &'a L,
        feature_depth: u32,
    ) -> Self {
        Self {
            advisory: Processor::Advisory(advisory::AdvisoryProcessor::new(grapher, locator, feature_depth)),
            license: Processor::License(license::LicenseProcessor::new(grapher, locator, feature_depth)),
            ban: Processor::Ban(ban::BanProcessor::new(grapher, locator, feature_depth)),
            source: Processor::Source(other::OtherProcessor::new(grapher, locator, feature_depth)),
            other: Processor::Other(other::OtherProcessor::new(grapher, locator, feature_depth)),
        }
    }

    pub fn get(&self, code: DiagnosticCode) -> &Processor<'a, L> {
        match code {
            DiagnosticCode::Advisory(_) => &self.advisory,
            DiagnosticCode::License(_) => &self.license,
            DiagnosticCode::Bans(_) => &self.ban,
            DiagnosticCode::Source(_) => &self.source,
            DiagnosticCode::General(_) => &self.other,
        }
    }
}

/// Shared helper: Creates a dummy location for advisories when no actual location can be determined.
pub(crate) fn create_dummy_location(workspace_root: &str) -> Location {
    use crate::sarif::model::{ArtifactLocation, PhysicalLocation, Region};
    
    Location {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation {
                uri: workspace_root.to_string(),
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

/// Shared helper: Creates a location from a krate.
/// For registry crates, uses the source to make it clear it's not a workspace crate.
/// For local crates, uses the actual manifest path.
pub(crate) fn create_location_from_krate(krate: &Krate) -> Location {
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
            artifact_location: ArtifactLocation { uri },
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

