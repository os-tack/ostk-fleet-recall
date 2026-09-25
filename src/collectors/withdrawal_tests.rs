//! The withdrawal rules: which channel may lift what, and when a refusal is a
//! narrowing rather than a first sighting or a stale report.

use super::*;

const VERIFIED: TrustTierV1 = TrustTierV1::Verified;
const REPORTED: TrustTierV1 = TrustTierV1::Reported;

const fn stored(access: ContainerAccessV1, tier: TrustTierV1) -> StoredContainerV1 {
    StoredContainerV1 { access, tier }
}

const PUBLIC: AudienceDecisionV1 = AudienceDecisionV1::Admit(AudienceBasisV1::ProviderPublic);
const DECLARED: AudienceDecisionV1 = AudienceDecisionV1::Admit(AudienceBasisV1::OperatorDeclared);
const SHARED: AudienceDecisionV1 = AudienceDecisionV1::Refuse(AudienceRefusalV1::ExternallyShared);
const PRIVATE: AudienceDecisionV1 =
    AudienceDecisionV1::Refuse(AudienceRefusalV1::RestrictedUnlisted);
const UNDECLARED: AudienceDecisionV1 =
    AudienceDecisionV1::Refuse(AudienceRefusalV1::OperatorDeclarationRequired);

#[test]
fn a_report_never_reopens_a_container_a_verification_withdrew() {
    let withdrawn = Some(stored(ContainerAccessV1::Withdrawn, VERIFIED));
    // An operator import of an older export, where the channel was public.
    assert_eq!(
        container_write(withdrawn, DECLARED, REPORTED),
        ContainerWriteV1::Keep
    );
    // A pull that sees it public again re-opens it.
    assert_eq!(
        container_write(withdrawn, PUBLIC, VERIFIED),
        ContainerWriteV1::Record(AudienceBasisV1::ProviderPublic)
    );
    // Nor does a report relabel what a verification recorded as readable.
    assert_eq!(
        container_write(
            Some(stored(ContainerAccessV1::Ok, VERIFIED)),
            DECLARED,
            REPORTED
        ),
        ContainerWriteV1::Keep
    );
}

#[test]
fn a_report_lifts_only_a_withdrawal_a_report_made() {
    // An import run without the declaration withdrew it; the corrected import
    // re-opens it.
    let withdrawn = Some(stored(ContainerAccessV1::Withdrawn, REPORTED));
    assert_eq!(
        container_write(withdrawn, DECLARED, REPORTED),
        ContainerWriteV1::Record(AudienceBasisV1::OperatorDeclared)
    );
    // Once a verified channel confirms the withdrawal, no report lifts it.
    assert_eq!(
        container_write(withdrawn, SHARED, VERIFIED),
        ContainerWriteV1::Confirm
    );
    let confirmed = Some(stored(ContainerAccessV1::Withdrawn, VERIFIED));
    assert_eq!(
        container_write(confirmed, DECLARED, REPORTED),
        ContainerWriteV1::Keep
    );
    // A report refusing a verified withdrawal again changes nothing.
    assert_eq!(
        container_write(confirmed, PRIVATE, REPORTED),
        ContainerWriteV1::Keep
    );
}

#[test]
fn any_channel_may_withdraw_a_readable_container() {
    for (row, observer) in [
        (VERIFIED, VERIFIED),
        (VERIFIED, REPORTED),
        (REPORTED, VERIFIED),
        (REPORTED, REPORTED),
    ] {
        assert_eq!(
            container_write(Some(stored(ContainerAccessV1::Ok, row)), PRIVATE, observer),
            ContainerWriteV1::Withdraw
        );
    }
}

#[test]
fn a_refused_container_never_recorded_is_recorded_withdrawn_only_on_a_fact() {
    assert_eq!(
        container_write(None, SHARED, VERIFIED),
        ContainerWriteV1::RecordWithdrawn
    );
    assert_eq!(
        container_write(None, PRIVATE, REPORTED),
        ContainerWriteV1::RecordWithdrawn
    );
    assert_eq!(
        container_write(
            None,
            AudienceDecisionV1::Refuse(AudienceRefusalV1::DirectMessage),
            VERIFIED
        ),
        ContainerWriteV1::RecordWithdrawn
    );
    // An instance without the operator's declaration says nothing about the
    // container itself.
    assert_eq!(
        container_write(None, UNDECLARED, REPORTED),
        ContainerWriteV1::Keep
    );
    assert_eq!(
        container_write(None, PUBLIC, VERIFIED),
        ContainerWriteV1::Record(AudienceBasisV1::ProviderPublic)
    );
}

#[test]
fn only_channels_with_audience_facts_withdraw_or_lift_items() {
    assert!(observes_item_audience(CollectionModeV1::Pull));
    assert!(observes_item_audience(CollectionModeV1::Push));
    assert!(observes_item_audience(CollectionModeV1::Import));
    assert!(!observes_item_audience(CollectionModeV1::Capture));
    assert!(narrows_item(AudienceRefusalV1::RestrictedUnlisted));
    assert!(!narrows_item(AudienceRefusalV1::ContainerWithdrawn));
    assert!(narrows_item(AudienceRefusalV1::HintRefused));
    assert!(!narrows_item(
        AudienceRefusalV1::OperatorDeclarationRequired
    ));
    assert!(!narrows_item(AudienceRefusalV1::AudienceUnknown));
    assert!(!narrows_item(AudienceRefusalV1::CaptureUnverified));
}

const fn row(withdrawn: bool, order: u64) -> ItemWithdrawalStateV1 {
    ItemWithdrawalStateV1 { withdrawn, order }
}

#[test]
fn a_first_sighting_is_not_a_narrowing() {
    assert_eq!(after_refusal(None, 2_000, false, None), None);
}

#[test]
fn a_refusal_of_an_admitted_item_withdraws_it() {
    // Admitted at 1000 in a public team, then seen at 2000 in a private one.
    assert_eq!(
        after_refusal(None, 2_000, true, Some(1_000)),
        Some(row(true, 2_000))
    );
    // At the same order, the refusal is the later observation and wins.
    assert_eq!(
        after_refusal(None, 1_000, true, Some(1_000)),
        Some(row(true, 1_000))
    );
    // Only reported parts are staged: nothing a verified refusal must yield
    // to.
    assert_eq!(
        after_refusal(None, 2_000, true, None),
        Some(row(true, 2_000))
    );
}

#[test]
fn a_stale_refusal_changes_nothing() {
    // A newer admissible version is already staged or admitted.
    assert_eq!(after_refusal(None, 1_500, true, Some(3_000)), None);
    // The row already decided a newer order.
    assert_eq!(
        after_refusal(Some(row(false, 3_000)), 1_500, true, None),
        None
    );
    assert_eq!(
        after_refusal(Some(row(true, 3_000)), 1_500, true, None),
        None
    );
    // The same withdrawal again is no write.
    assert_eq!(
        after_refusal(Some(row(true, 3_000)), 3_000, true, None),
        None
    );
    // A newer refusal moves a withdrawal forward, or withdraws a lifted item
    // again.
    assert_eq!(
        after_refusal(Some(row(true, 3_000)), 4_000, true, None),
        Some(row(true, 4_000))
    );
    assert_eq!(
        after_refusal(Some(row(false, 3_000)), 3_000, true, None),
        Some(row(true, 3_000))
    );
}

#[test]
fn an_admission_at_an_order_at_least_as_great_lifts() {
    // Moved back into a public team.
    assert_eq!(
        after_admission(row(true, 2_000), 3_000),
        Some(row(false, 3_000))
    );
    // The operator listed the private team; the item is read again at its
    // own order.
    assert_eq!(
        after_admission(row(true, 2_000), 2_000),
        Some(row(false, 2_000))
    );
    // An older admissible version arriving late does not lift.
    assert_eq!(after_admission(row(true, 2_000), 1_000), None);
    // A lifted row remembers a greater order, and nothing else.
    assert_eq!(
        after_admission(row(false, 2_000), 2_500),
        Some(row(false, 2_500))
    );
    assert_eq!(after_admission(row(false, 2_000), 2_000), None);
}

#[test]
fn a_report_never_lifts_an_item_a_verification_withdrew() {
    assert!(may_lift(VERIFIED, VERIFIED));
    assert!(may_lift(VERIFIED, REPORTED));
    assert!(may_lift(REPORTED, REPORTED));
    assert!(!may_lift(REPORTED, VERIFIED));
}
