//! Private persistence boundary for the one genesis registry activation.

mod cockroach;
mod generic_successor_cockroach;
mod generic_successor_repository;
mod genesis_audit;
mod repository;
mod successor_cockroach;
mod successor_repository;

pub use cockroach::CockroachGenesisActivationRepository;
pub use generic_successor_cockroach::CockroachGenericSuccessorRepository;
pub use generic_successor_repository::{
    AcceptedGenericSuccessorActivation, GenericSuccessorActivationCandidate,
    GenericSuccessorActivationInspection, GenericSuccessorActivationOutcome,
    GenericSuccessorRepository, ReadyGenericSuccessor,
};
pub use repository::{
    AcceptedGenesisActivation, GenesisActivationInspection, GenesisActivationOutcome,
    GenesisActivationRepository, PinnedInactiveGenesis,
};
pub use successor_cockroach::CockroachSuccessorActivationRepository;
pub use successor_repository::{
    AcceptedSuccessorActivation, ReadySuccessorActivation, SuccessorActivationCandidate,
    SuccessorActivationInspection, SuccessorActivationOutcome, SuccessorActivationRepository,
};
