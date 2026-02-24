//! Concrete agent implementations for each pipeline role.

pub mod analyst;
pub mod executor;
pub mod reporter;
pub mod researcher;
pub mod strategist;

pub use analyst::AnalystAgent;
pub use executor::ExecutorAgent;
pub use reporter::ReporterAgent;
pub use researcher::ResearcherAgent;
pub use strategist::StrategistAgent;
