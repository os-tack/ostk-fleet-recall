//! Private persistence boundary for the one genesis registry activation.
//!
//! [`install`] drives the whole signed chain (control bootstrap, genesis,
//! `0 -> 1`, `1 -> 2`) for one physical scope in a single idempotent call.

mod cockroach;
mod generic_successor_cockroach;
mod generic_successor_repository;
mod genesis_audit;
pub mod install;
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
