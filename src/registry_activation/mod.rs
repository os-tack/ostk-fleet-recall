//! Private persistence boundary for the one genesis registry activation.

mod cockroach;
mod repository;

pub use cockroach::CockroachGenesisActivationRepository;
pub use repository::{
    AcceptedGenesisActivation, GenesisActivationInspection, GenesisActivationOutcome,
    GenesisActivationRepository, PinnedInactiveGenesis,
};
