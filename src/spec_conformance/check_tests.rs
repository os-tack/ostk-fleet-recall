use super::*;
use crate::spec_conformance::testkit::commit;

fn sources(json: &serde_json::Value) -> WorkerSourcesV1 {
    WorkerSourcesV1::from_json_slice(&serde_json::to_vec(json).unwrap()).unwrap()
}

fn request(sources: WorkerSourcesV1) -> SpecCheckRequestV1 {
    SpecCheckRequestV1 {
        binding_family_id: ContractId::new("spec.remember.no_forget").unwrap(),
        sources,
        git_source: ContractId::new("connector.git.main").unwrap(),
        commit: commit(),
        member_bound: DEFAULT_SPEC_MEMBER_BOUND,
        evaluated_through: None,
    }
}

fn git_source(provider_repository_id: Option<u64>) -> serde_json::Value {
    let mut source = serde_json::json!({
        "connector_principal": "connector.git",
        "connector_instance": "connector.git.main",
        "installation_id": 4242,
        "repository_id": "git.repo.main",
        "git_dir": "/srv/repo.git",
        "ref_name": "refs/heads/main"
    });
    if let Some(id) = provider_repository_id {
        source["provider_repository_id"] = id.into();
    }
    source
}

#[test]
fn a_check_reads_the_workers_git_source_and_observer_identity() {
    let configured = request(sources(&serde_json::json!({
        "schema_version": 1,
        "git": [git_source(Some(908_172_635))],
        "observer": {
            "connector_principal": "connector.observer",
            "connector_instance": "connector.observer.spec"
        }
    })));
    let (git, provider_repository_id) = configured.git().unwrap();
    assert_eq!(git.connector_instance.as_str(), "connector.git.main");
    assert_eq!(provider_repository_id, 908_172_635);
    assert_eq!(
        configured.observer().unwrap().connector_instance.as_str(),
        "connector.observer.spec"
    );
}

#[test]
fn a_sources_file_the_check_cannot_use_is_refused_before_any_read() {
    let without_provider_id = request(sources(&serde_json::json!({
        "schema_version": 1,
        "git": [git_source(None)]
    })));
    assert!(matches!(
        without_provider_id.git(),
        Err(FleetError::Configuration(_))
    ));
    assert!(matches!(
        without_provider_id.observer(),
        Err(FleetError::Configuration(_))
    ));

    let mut another_source = request(sources(&serde_json::json!({
        "schema_version": 1,
        "git": [git_source(Some(1))]
    })));
    another_source.git_source = ContractId::new("connector.git.other").unwrap();
    assert!(matches!(
        another_source.git(),
        Err(FleetError::Configuration(_))
    ));
}
