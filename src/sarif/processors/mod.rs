pub mod advisory;
pub mod other;

use crate::diag::{Diag, Files};
use crate::sarif::model::Location;
use crate::Kid;
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
    Other(other::OtherProcessor<'a, L>),
}

/// Set of all processors, organized by diagnostic variant
pub struct ProcessorSet<'a, L: LocationFinder> {
    advisory: Processor<'a, L>,
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
            other: Processor::Other(other::OtherProcessor::new(grapher, locator, feature_depth)),
        }
    }

    pub fn get(&self, code: DiagnosticCode) -> &Processor<'a, L> {
        match code {
            DiagnosticCode::Advisory(_) => &self.advisory,
            _ => &self.other,
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
                message: Some(Message::text("Unable to determine dependency location".to_string())),
            },
        },
    }
}
