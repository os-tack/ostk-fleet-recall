//! Private persistence boundary for the one genesis registry activation.

mod cockroach;
mod genesis_audit;
mod repository;
mod successor_cockroach;
mod successor_repository;

pub use cockroach::CockroachGenesisActivationRepository;
pub use repository::{
    AcceptedGenesisActivation, GenesisActivationInspection, GenesisActivationOutcome,
    GenesisActivationRepository, PinnedInactiveGenesis,
};
pub use successor_cockroach::CockroachSuccessorActivationRepository;
pub use successor_repository::{
    AcceptedSuccessorActivation, ReadySuccessorActivation, SuccessorActivationCandidate,
    SuccessorActivationInspection, SuccessorActivationOutcome, SuccessorActivationRepository,
};
