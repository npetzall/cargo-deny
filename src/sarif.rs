mod collector;
mod locator;
pub mod model;
pub mod processors;

pub use collector::SarifCollector;
pub use locator::{LocationFinder, Locator};
pub use processors::ProcessorSet;
