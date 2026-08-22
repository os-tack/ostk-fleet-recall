//! Per-row visibility classification for the recall projection (W2-VIS).
//!
//! This module is pure: no database, no I/O. It answers one question — may the
//! publication plane see the rows derived from this accepted evidence event? —
//! and it names the exact SQL objects the two planes read.
//!
//! # The classification
//!
//! An accepted `EvidenceStatementV2` carries the server-derived governance
//! envelope described in the architecture document as "server-derived
//! visibility/protection domain": a [`VisibilityClass`], a [`PublicationClass`],
//! and the protection domain of the governed content. A body derived from that
//! event is [`RowVisibilityClassV1::PublicationSafe`] only when ALL THREE of the
//! following hold, and [`RowVisibilityClassV1::Private`] otherwise:
//!
//! 1. `visibility_class == VisibilityClass::PublicationApproved`,
//! 2. `publication_class == PublicationClass::PublicationApproved`,
//! 3. the governed content's `protection_domain_id` is exactly the event's own
//!    authenticated `scope.project_namespace`.
//!
//! Conjunct 3 is the protection-domain binding. The admission seam sets the
//! protection domain from the credential-bound project namespace, so an event
//! whose content claims a foreign protection domain is one whose governance
//! decision was made somewhere this scope does not speak for. Such an event is
//! classified private, whatever its two classes say.
//!
//! The function is total and fails closed: `Private` is returned for every
//! combination that is not the exact approved triple, so a new enum variant
//! added upstream can only ever make a row MORE private, never less.
//!
//! # Where the decision is enforced
//!
//! Nowhere in Rust. The class is stored on the projection row and the predicate
//! lives INSIDE the lexical and dense SQL, ahead of ranking — see
//! [`super::cockroach`]. The publication plane goes further and reads through
//! [`PUBLICATION_PLANE_VIEWS`], filtered projections that structurally cannot
//! name a private row; the public database role is granted those views and
//! nothing else, so a private row is not merely filtered out of its answers, it
//! is outside its privilege set entirely (PUBLIC-03, PUBLIC-04).

use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::evidence::{PublicationClass, VisibilityClass};
use crate::memory_contracts::evidence_v2::EvidenceStatementV2;

use super::error::{RecallProjectionError, RecallProjectionResult};

/// Stored `visibility_class` of one projection row.
///
/// Two values only. The three-valued upstream [`VisibilityClass`] is a
/// classification of evidence; this is the physical read-plane decision the
/// recall queries and the publication views compare against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RowVisibilityClassV1 {
    /// Readable only by the private plane.
    Private,
    /// Also readable through the publication plane.
    PublicationSafe,
}

impl RowVisibilityClassV1 {
    /// Exact stored column value. Part of the schema contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::PublicationSafe => "publication_safe",
        }
    }

    /// Parse a stored `visibility_class` value. Unknown values fail closed with
    /// a typed error rather than defaulting to either class.
    pub fn parse(value: &str) -> RecallProjectionResult<Self> {
        match value {
            "private" => Ok(Self::Private),
            "publication_safe" => Ok(Self::PublicationSafe),
            other => Err(RecallProjectionError::ProjectionIntegrity(format!(
                "stored projection row names an unknown visibility class: {other}"
            ))),
        }
    }

    /// Whether this class may leave the private plane.
    #[must_use]
    pub const fn is_publication_safe(self) -> bool {
        matches!(self, Self::PublicationSafe)
    }
}

/// Which read plane a [`super::CockroachRecallReader`] answers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallPlaneV1 {
    /// The private plane: sees every row of its own scope, both classes.
    Private,
    /// The publication plane: reads the publication views only.
    Publication,
}

impl RecallPlaneV1 {
    /// Whether this plane may see private rows.
    #[must_use]
    pub const fn admits_private_rows(self) -> bool {
        matches!(self, Self::Private)
    }
}

/// Exact stored value of an evidence [`VisibilityClass`].
#[must_use]
pub const fn evidence_visibility_label(class: VisibilityClass) -> &'static str {
    match class {
        VisibilityClass::Private => "private",
        VisibilityClass::Project => "project",
        VisibilityClass::PublicationApproved => "publication_approved",
    }
}

/// Exact stored value of an evidence [`PublicationClass`].
#[must_use]
pub const fn evidence_publication_label(class: PublicationClass) -> &'static str {
    match class {
        PublicationClass::Denied => "denied",
        PublicationClass::PrivateOnly => "private_only",
        PublicationClass::PublicationApproved => "publication_approved",
    }
}

/// Classify one governance envelope. Total, pure, and fail-closed: everything
/// that is not the exact approved triple is [`RowVisibilityClassV1::Private`].
#[must_use]
pub fn classify_row_visibility(
    visibility_class: VisibilityClass,
    publication_class: PublicationClass,
    protection_domain_id: &ContractId,
    authenticated_project_namespace: &ContractId,
) -> RowVisibilityClassV1 {
    let approved = matches!(visibility_class, VisibilityClass::PublicationApproved)
        && matches!(publication_class, PublicationClass::PublicationApproved)
        && protection_domain_id == authenticated_project_namespace;
    if approved {
        RowVisibilityClassV1::PublicationSafe
    } else {
        RowVisibilityClassV1::Private
    }
}

/// The governance envelope one accepted evidence event contributes to every
/// body derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyVisibilityV1 {
    /// The read-plane decision stored on every projection row.
    pub class: RowVisibilityClassV1,
    /// Protection domain of the governed content, stored verbatim.
    pub protection_domain_id: ContractId,
    /// The event's own visibility class, stored verbatim for audit.
    pub source_visibility_class: VisibilityClass,
    /// The event's own publication class, stored verbatim for audit.
    pub source_publication_class: PublicationClass,
}

impl BodyVisibilityV1 {
    /// Derive the envelope from one accepted evidence statement.
    ///
    /// The statement's own `scope.project_namespace` is the authenticated
    /// namespace conjunct 3 compares against: it is server context, never a
    /// payload field a producer chooses (`AuthenticatedProjectScopeV1`).
    #[must_use]
    pub fn from_statement(statement: &EvidenceStatementV2) -> Self {
        Self {
            class: classify_row_visibility(
                statement.visibility_class,
                statement.publication_class,
                &statement.canonical_content.protection_domain_id,
                &statement.scope.project_namespace,
            ),
            protection_domain_id: statement.canonical_content.protection_domain_id.clone(),
            source_visibility_class: statement.visibility_class,
            source_publication_class: statement.publication_class,
        }
    }

    /// Stored `source_visibility_class` value.
    #[must_use]
    pub const fn source_visibility_label(&self) -> &'static str {
        evidence_visibility_label(self.source_visibility_class)
    }

    /// Stored `source_publication_class` value.
    #[must_use]
    pub const fn source_publication_label(&self) -> &'static str {
        evidence_publication_label(self.source_publication_class)
    }
}

/// The per-body visibility table (migration 0023).
pub const BODY_VISIBILITY_TABLE: &str = "memory_body_visibility_v1";

/// The two publication-plane views (migration 0023) — the entire SQL surface
/// the public reader role is granted.
pub const PUBLICATION_PLANE_VIEWS: [&str; 2] = [
    "memory_body_lexical_publication_v1",
    "memory_body_dense_publication_v1",
];

/// The private-plane recall tables. The publication role must never hold a
/// grant on any of these; they are listed here so the boundary is asserted
/// against a name list rather than remembered.
pub const PRIVATE_PLANE_RECALL_TABLES: [&str; 4] = [
    "memory_body_lexical_projection_v1",
    "memory_body_dense_projection_v1",
    "memory_recall_projection_cursors_v1",
    BODY_VISIBILITY_TABLE,
];

/// The exact grant statements the deployment role-grant job must apply so the
/// publication reader can serve body recall.
///
/// Migration 0023 deliberately installs no grant (it creates no role, and the
/// role policy is a cluster-admin ceremony). This function is the single
/// machine-readable definition of what that ceremony adds, so the deployment
/// job and `tests/visibility_live.rs` cannot drift apart. It names VIEWS only:
/// the reader gets no privilege on any base table, which is what makes a
/// private row unreachable rather than merely unselected.
#[must_use]
pub fn publication_plane_grant_statements(role: &str) -> Vec<String> {
    PUBLICATION_PLANE_VIEWS
        .iter()
        .map(|view| format!("GRANT SELECT ON TABLE public.{view} TO {role}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(value: &str) -> ContractId {
        ContractId::new(value).unwrap()
    }

    #[test]
    fn stored_class_names_round_trip_and_reject_unknown_values() {
        for class in [
            RowVisibilityClassV1::Private,
            RowVisibilityClassV1::PublicationSafe,
        ] {
            assert_eq!(RowVisibilityClassV1::parse(class.as_str()).unwrap(), class);
        }
        // Fail closed: an unknown stored value is never coerced to either
        // class, and in particular never silently read as publication-safe.
        for unknown in ["", "PRIVATE", "public", "publication-safe", "project"] {
            assert!(
                RowVisibilityClassV1::parse(unknown).is_err(),
                "{unknown} must not parse"
            );
        }
    }

    #[test]
    fn the_exact_approved_triple_is_the_only_publication_safe_input() {
        assert_eq!(
            classify_row_visibility(
                VisibilityClass::PublicationApproved,
                PublicationClass::PublicationApproved,
                &domain("project.fixture"),
                &domain("project.fixture"),
            ),
            RowVisibilityClassV1::PublicationSafe
        );
    }

    #[test]
    fn an_unapproved_visibility_class_stays_private() {
        // Conjunct 1. Killing test for "the visibility class is ignored".
        for visibility in [VisibilityClass::Private, VisibilityClass::Project] {
            assert_eq!(
                classify_row_visibility(
                    visibility,
                    PublicationClass::PublicationApproved,
                    &domain("project.fixture"),
                    &domain("project.fixture"),
                ),
                RowVisibilityClassV1::Private,
                "{visibility:?} must not reach the publication plane"
            );
        }
    }

    #[test]
    fn an_unapproved_publication_class_stays_private() {
        // Conjunct 2. Killing test for "publication approval is inferred from
        // the visibility class alone".
        for publication in [PublicationClass::Denied, PublicationClass::PrivateOnly] {
            assert_eq!(
                classify_row_visibility(
                    VisibilityClass::PublicationApproved,
                    publication,
                    &domain("project.fixture"),
                    &domain("project.fixture"),
                ),
                RowVisibilityClassV1::Private,
                "{publication:?} must not reach the publication plane"
            );
        }
    }

    #[test]
    fn a_foreign_protection_domain_stays_private() {
        // Conjunct 3. Killing test for dropping the protection-domain binding:
        // approval granted under some other domain's governance is not approval
        // here, however approved the two classes look.
        assert_eq!(
            classify_row_visibility(
                VisibilityClass::PublicationApproved,
                PublicationClass::PublicationApproved,
                &domain("project.other"),
                &domain("project.fixture"),
            ),
            RowVisibilityClassV1::Private
        );
    }

    #[test]
    fn every_unapproved_combination_of_the_two_classes_is_private() {
        // Exhaustive over the 3x3 class product: exactly one cell is
        // publication-safe, and it is the approved/approved cell.
        let visibilities = [
            VisibilityClass::Private,
            VisibilityClass::Project,
            VisibilityClass::PublicationApproved,
        ];
        let publications = [
            PublicationClass::Denied,
            PublicationClass::PrivateOnly,
            PublicationClass::PublicationApproved,
        ];
        let mut safe = 0_u32;
        for visibility in visibilities {
            for publication in publications {
                if classify_row_visibility(
                    visibility,
                    publication,
                    &domain("project.fixture"),
                    &domain("project.fixture"),
                )
                .is_publication_safe()
                {
                    safe += 1;
                    assert_eq!(visibility, VisibilityClass::PublicationApproved);
                    assert_eq!(publication, PublicationClass::PublicationApproved);
                }
            }
        }
        assert_eq!(safe, 1);
    }

    #[test]
    fn the_two_planes_disagree_only_about_private_rows() {
        assert!(RecallPlaneV1::Private.admits_private_rows());
        assert!(!RecallPlaneV1::Publication.admits_private_rows());
    }

    #[test]
    fn evidence_class_labels_match_the_migration_check_constraints() {
        // Migration 0023's CHECK constraints enumerate exactly these strings;
        // a rename here without a migration would make every append fail.
        assert_eq!(
            [
                evidence_visibility_label(VisibilityClass::Private),
                evidence_visibility_label(VisibilityClass::Project),
                evidence_visibility_label(VisibilityClass::PublicationApproved),
            ],
            ["private", "project", "publication_approved"]
        );
        assert_eq!(
            [
                evidence_publication_label(PublicationClass::Denied),
                evidence_publication_label(PublicationClass::PrivateOnly),
                evidence_publication_label(PublicationClass::PublicationApproved),
            ],
            ["denied", "private_only", "publication_approved"]
        );
    }

    #[test]
    fn the_publication_grant_surface_names_views_only() {
        // The load-bearing deployment claim: the public role's whole privilege
        // set is two views. If a base table ever appeared here, a private row
        // would become reachable by direct SQL even though every query filtered
        // it out.
        let statements = publication_plane_grant_statements("fleet_publication_reader");
        assert_eq!(statements.len(), PUBLICATION_PLANE_VIEWS.len());
        for statement in &statements {
            assert!(statement.starts_with("GRANT SELECT ON TABLE public."));
            assert!(statement.ends_with(" TO fleet_publication_reader"));
            for private in PRIVATE_PLANE_RECALL_TABLES {
                assert!(
                    !statement.contains(private),
                    "{private} must never be granted to the publication role: {statement}"
                );
            }
        }
        for view in PUBLICATION_PLANE_VIEWS {
            assert!(statements.iter().any(|statement| statement.contains(view)));
        }
    }

    #[test]
    fn no_publication_view_shares_a_name_with_a_private_table() {
        for view in PUBLICATION_PLANE_VIEWS {
            assert!(!PRIVATE_PLANE_RECALL_TABLES.contains(&view));
        }
        // The projection tiers also stay off the legacy public read inventory,
        // which is the rest of the public plane's surface.
        for private in PRIVATE_PLANE_RECALL_TABLES {
            assert!(!crate::store::cockroach::PUBLICATION_READ_TABLES.contains(&private));
        }
    }
}
