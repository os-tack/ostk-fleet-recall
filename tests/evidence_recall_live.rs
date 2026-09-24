//! Connected proof for evidence recall (`ostk_fleet_recall::evidence_recall`).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database; every test here is inert otherwise. Each test installs a real
//! generation-2 writer authority into a fresh physical tenant and runs real
//! memory-worker ticks over a scratch git repository, a scratch transcript
//! directory, and the recorded CI corpus (the shared `tests/common` worker
//! fixture), then reads the result back the way serving will.
//!
//! What it proves: a search finds each connector's evidence and hydrates it
//! with recall text, media type, and the accepted event behind it; an empty
//! answer is `absent` only while the lexical tier is current and every source
//! is healthy, fresh, and completely covered, and turns `unknown`, naming why,
//! when evidence is waiting for projection, a source fails, or a source's
//! last check goes stale; a query of stopwords or punctuation is an `unknown`
//! answer, not an error; a body's full text comes back by id and nothing comes
//! back for an id that is not in the scope; and the startup probe refuses a
//! login that cannot read the Stage-5 tables while the runtime grants suffice
//! for every read.
//!
//! Served over MCP (ADR 0006), composed as `serve` composes it: `tools/list`
//! advertises `kind=evidence` exactly where the probe finds the Stage-5 tables
//! readable, `recall` answers evidence search, get, and status through the
//! server's real newline framing, and a login without the Stage-5 grants
//! keeps every tool schema and every error text byte for byte what it was.

mod common;

use std::sync::Arc;

use common::authority::retry_policy;
use common::runtime_role::RuntimeProbeRole;
use common::worker::{
    COMMIT_WORD, FAILING_STEP_WORD, GIT_INSTANCE, STUB_MODEL_DIGEST, StubEmbedder, TRANSCRIPT_WORD,
    WorkerFixture,
};
use ostk_fleet_recall::evidence_recall::{
    AbsenceReasonV1, AbsenceVerdictV1, CockroachEvidenceRecall, EvidenceDenseLaneV1,
    EvidenceMatchV1, EvidenceRecall, EvidenceSearchV1, probe_evidence_recall,
    start_evidence_recall,
};
use ostk_fleet_recall::ledger::CockroachClaimLedger;
use ostk_fleet_recall::mcp::{McpServer, tool_list, tool_list_for_surfaces};
use ostk_fleet_recall::memory_contracts::coverage::CoverageCompletenessV1;
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::service::{RecallSurface, RememberSurface};
use ostk_fleet_recall::store::cockroach::{CockroachStore, DatabaseCapabilities, PoolConfig};
use ostk_fleet_recall::worker::{WorkerSourceOutcomeV1, WorkerStepStatusV1, WorkerStepV1};
use ostk_fleet_recall::{CockroachMemoryService, FleetScope};
use ostk_recall_core::ChunkEmbedder;
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::io::{
    AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf,
};
use tokio::task::JoinHandle;

/// Words no fixture source contains.
const NONSENSE: &str = "xylophagous quokkaberry";

/// A word only the commit a test adds contains.
const LATE_WORD: &str = "brindlewort";
const LATE_COMMIT_DATE: &str = "1755432000 +0000";

async fn capabilities(database_url: &str) -> DatabaseCapabilities {
    CockroachStore::connect(
        database_url,
        common::fresh_scope("evidence-capabilities"),
        PoolConfig::default(),
    )
    .await
    .expect("the owner must connect")
    .capabilities()
    .await
    .expect("the owner reads capabilities")
}

/// Evidence recall for `scope` over `pool`, probed with the stub model.
async fn evidence(
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
) -> CockroachEvidenceRecall {
    let capability = probe_evidence_recall(
        pool,
        capabilities,
        scope,
        Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
    )
    .await
    .expect("the probe runs")
    .expect("the login may read every evidence table");
    CockroachEvidenceRecall::new(capability, pool.clone())
}

fn query_vector(query: &str) -> Vec<f32> {
    StubEmbedder.encode_batch(&[query]).remove(0)
}

/// A worker tick of `steps` that must not fail.
async fn tick(fixture: &WorkerFixture, pool: &PgPool, steps: &str) {
    let report = fixture.worker(pool, steps).await.run_tick().await;
    assert!(
        !report.failed(),
        "the {steps} tick must succeed: {}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}

async fn search(recall: &CockroachEvidenceRecall, query: &str) -> EvidenceSearchV1 {
    recall
        .search(query, None, 10)
        .await
        .unwrap_or_else(|error| panic!("search {query:?}: {error}"))
}

fn assert_absent(answer: &EvidenceSearchV1) {
    assert!(answer.hits.is_empty());
    assert_eq!(
        answer.absence.verdict,
        AbsenceVerdictV1::Absent,
        "{:?}; sources {:?}",
        answer.absence,
        answer.sources
    );
}

fn assert_unknown_because(answer: &EvidenceSearchV1, reasons: &[AbsenceReasonV1]) {
    assert!(answer.hits.is_empty(), "{:?}", answer.hits);
    assert_eq!(answer.absence.verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(answer.absence.reasons, reasons, "{:?}", answer.sources);
}

async fn event_exists(pool: &PgPool, fixture: &WorkerFixture, event_id: Sha256Digest) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 AND event_id = $3)",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(event_id.as_bytes().as_slice())
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn live_evidence_search_hydrates_hits_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let fixture = WorkerFixture::install(&pool, "evidence-search").await;
    tick(&fixture, &pool, "all").await;
    let recall = evidence(&pool, &capabilities, &fixture.installed.scope).await;

    for word in [COMMIT_WORD, TRANSCRIPT_WORD, FAILING_STEP_WORD] {
        let answer = recall
            .search(word, Some(query_vector(word)), 10)
            .await
            .unwrap();
        assert_eq!(answer.absence.verdict, AbsenceVerdictV1::Present, "{word}");
        assert_eq!(answer.readiness.dense_lane, EvidenceDenseLaneV1::Used);
        let mut found = false;
        for hit in &answer.hits {
            assert!(!hit.media_type.is_empty());
            assert!(hit.snippet.chars().count() <= 600);
            if let Some(similarity) = hit.dense_similarity {
                assert!(similarity >= 0.18, "{hit:?} is below the dense floor");
            }
            let body = recall
                .get(hit.id)
                .await
                .unwrap()
                .expect("a hit's body is readable by its id");
            assert!(body.text.starts_with(&hit.snippet));
            assert_eq!(hit.snippet_truncated, body.text.len() > hit.snippet.len());
            assert_eq!(body.first_accepted_event_id, hit.first_accepted_event_id);
            if body.text.to_lowercase().contains(&word.to_lowercase()) {
                assert!(
                    matches!(
                        hit.matched_by,
                        EvidenceMatchV1::Lexical | EvidenceMatchV1::LexicalAndDense
                    ) && hit.lexical_score.is_some(),
                    "{hit:?}"
                );
                assert!(
                    event_exists(&pool, &fixture, hit.first_accepted_event_id).await,
                    "a hit names an accepted event of this scope"
                );
                found = true;
            }
        }
        assert!(found, "no hit's text carries {word:?}: {:?}", answer.hits);
    }

    let status = recall.status().await.unwrap();
    assert!(status.readiness.lexical_current && status.readiness.dense_current);
    assert_eq!(status.readiness.dense_lane, EvidenceDenseLaneV1::Available);
    assert!(!status.sources.truncated);
    assert!(
        status
            .sources
            .active
            .iter()
            .any(|source| source.connector_instance == GIT_INSTANCE)
    );
    for source in &status.sources.active {
        assert_eq!(source.last_outcome, WorkerSourceOutcomeV1::Ok, "{source:?}");
        assert!(
            source.last_checked_at.is_some() && !source.stale,
            "{source:?}"
        );
        let coverage = source.coverage.as_ref().expect("every source has coverage");
        assert_eq!(coverage.completeness, CoverageCompletenessV1::Complete);
    }

    // A process whose model is not the one the dense tier was embedded with
    // serves the lexical lane only.
    let foreign = probe_evidence_recall(
        &pool,
        &capabilities,
        &fixture.installed.scope,
        Sha256Digest::from_bytes([0x11; 32]),
    )
    .await
    .unwrap()
    .expect("the login may read every evidence table");
    assert_eq!(
        foreign.dense_lane(),
        EvidenceDenseLaneV1::DisabledForeignModel
    );
    let foreign = CockroachEvidenceRecall::new(foreign, pool.clone());
    let answer = foreign
        .search(COMMIT_WORD, Some(query_vector(COMMIT_WORD)), 10)
        .await
        .unwrap();
    assert_eq!(
        answer.readiness.dense_lane,
        EvidenceDenseLaneV1::DisabledForeignModel
    );
    assert!(!answer.hits.is_empty());
    assert!(
        answer
            .hits
            .iter()
            .all(|hit| hit.matched_by == EvidenceMatchV1::Lexical)
    );
}

#[tokio::test]
async fn live_evidence_absent_only_when_current_covered_and_fresh_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let fixture = WorkerFixture::install(&pool, "evidence-absence").await;
    let recall = evidence(&pool, &capabilities, &fixture.installed.scope).await;

    // Before any tick there is no source to vouch for anything.
    assert_unknown_because(
        &search(&recall, NONSENSE).await,
        &[AbsenceReasonV1::NoSourcesRegistered],
    );

    tick(&fixture, &pool, "all").await;
    let answer = search(&recall, NONSENSE).await;
    assert_absent(&answer);
    assert!(answer.absence.as_of.is_some());

    // A commit the worker has admitted but not projected leaves every empty
    // answer unknown, including one for the new commit's own word.
    let head = fixture.repository.head();
    fixture.repository.commit(
        Some(&head),
        &format!("retire the {LATE_WORD} fallback"),
        LATE_COMMIT_DATE,
    );
    tick(&fixture, &pool, "ingest").await;
    for query in [NONSENSE, LATE_WORD] {
        assert_unknown_because(
            &search(&recall, query).await,
            &[AbsenceReasonV1::BodyProjectionLag],
        );
    }
    tick(&fixture, &pool, "project,embed").await;
    assert_eq!(
        search(&recall, LATE_WORD).await.absence.verdict,
        AbsenceVerdictV1::Present
    );
    assert_absent(&search(&recall, NONSENSE).await);

    // A source whose last attempt failed makes absence unknown, even though
    // its earlier check and coverage stand.
    let moved = fixture.repository.path().with_extension("moved");
    std::fs::rename(fixture.repository.path(), &moved).unwrap();
    let report = fixture.worker(&pool, "ingest").await.run_tick().await;
    std::fs::rename(&moved, fixture.repository.path()).unwrap();
    assert_eq!(
        report.step(WorkerStepV1::Git).unwrap().status,
        WorkerStepStatusV1::Failed
    );
    let answer = search(&recall, NONSENSE).await;
    assert_unknown_because(&answer, &[AbsenceReasonV1::SourceFailed]);
    let git = answer
        .sources
        .active
        .iter()
        .find(|source| source.connector_instance == GIT_INSTANCE)
        .unwrap();
    assert_eq!(git.last_outcome, WorkerSourceOutcomeV1::Failed);
    assert!(git.last_error.is_some() && git.last_checked_at.is_some());

    tick(&fixture, &pool, "ingest").await;
    assert_absent(&search(&recall, NONSENSE).await);

    // A check older than the source's staleness bound no longer vouches for
    // absence.
    sqlx::query(
        "UPDATE memory_worker_sources_v1 \
         SET last_checked_at = last_checked_at - INTERVAL '2 days' \
         WHERE tenant_id = $1 AND project = $2 AND connector_instance_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(GIT_INSTANCE)
    .execute(&pool)
    .await
    .unwrap();
    let answer = search(&recall, NONSENSE).await;
    assert_unknown_because(&answer, &[AbsenceReasonV1::SourceStale]);
    assert!(
        answer
            .sources
            .active
            .iter()
            .any(|source| source.connector_instance == GIT_INSTANCE && source.stale)
    );
}

#[tokio::test]
async fn live_stopword_query_is_unknown_not_error_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let fixture = WorkerFixture::install(&pool, "evidence-stopwords").await;
    tick(&fixture, &pool, "all").await;
    let recall = evidence(&pool, &capabilities, &fixture.installed.scope).await;

    for query in ["the and of", "what's up?", "?!() & |", ""] {
        assert_unknown_because(
            &search(&recall, query).await,
            &[AbsenceReasonV1::QueryHasNoLexicalTerms],
        );
    }
    // Punctuation the text-search parser would reject is searched as words.
    assert_eq!(
        search(&recall, &format!("{COMMIT_WORD}: (cache) & eviction!"))
            .await
            .absence
            .verdict,
        AbsenceVerdictV1::Present
    );
    // With a query vector the dense lane still runs; whatever it finds, a
    // query with no lexical terms is never absent.
    let answer = recall
        .search("the", Some(query_vector("the")), 10)
        .await
        .unwrap();
    assert_ne!(answer.absence.verdict, AbsenceVerdictV1::Absent);
}

#[tokio::test]
async fn live_get_returns_full_text_or_null_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let fixture = WorkerFixture::install(&pool, "evidence-get").await;
    tick(&fixture, &pool, "all").await;
    let recall = evidence(&pool, &capabilities, &fixture.installed.scope).await;

    let answer = search(&recall, COMMIT_WORD).await;
    let mut commit = None;
    for hit in &answer.hits {
        let body = recall
            .get(hit.id)
            .await
            .unwrap()
            .expect("a hit's body is readable by its id");
        if body.text.contains(COMMIT_WORD) {
            commit = Some((hit, body));
        }
    }
    let (hit, body) = commit.expect("the commit is recalled");
    assert_eq!(body.id, hit.id);
    assert!(body.text.starts_with(&hit.snippet));
    assert_eq!(usize::try_from(body.text_bytes).unwrap(), body.text.len());
    assert_eq!(body.media_type, hit.media_type);
    assert_eq!(body.first_accepted_event_id, hit.first_accepted_event_id);

    assert!(
        recall
            .get(Sha256Digest::from_bytes([0x42; 32]))
            .await
            .unwrap()
            .is_none()
    );

    // Another scope cannot read this scope's body, and has no source.
    let other_scope = common::fresh_scope("evidence-get-other");
    let other = evidence(&pool, &capabilities, &other_scope).await;
    assert!(other.get(hit.id).await.unwrap().is_none());
    assert_unknown_because(
        &search(&other, COMMIT_WORD).await,
        &[AbsenceReasonV1::NoSourcesRegistered],
    );
}

#[tokio::test]
async fn live_probe_refuses_without_select_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let fixture = WorkerFixture::install(&owner, "evidence-probe").await;
    tick(&fixture, &owner, "all").await;
    let digest = Sha256Digest::from_bytes(STUB_MODEL_DIGEST);

    let without = RuntimeProbeRole::create_worker(&owner, &database_url, false).await;
    let refused = probe_evidence_recall(
        &without.pool,
        &capabilities,
        &fixture.installed.scope,
        digest,
    )
    .await;
    without.drop_role(&owner).await;
    assert!(
        refused
            .expect("a missing privilege is not an error")
            .is_none(),
        "a login without the Stage-5 grants must not serve evidence recall"
    );

    let mut older = capabilities.clone();
    older.schema_version = 29;
    assert!(
        probe_evidence_recall(&owner, &older, &fixture.installed.scope, digest)
            .await
            .unwrap()
            .is_none(),
        "a schema before migration 30 has no worker status to read"
    );

    // The runtime grants are enough for every read.
    let role = RuntimeProbeRole::create_worker(&owner, &database_url, true).await;
    let reads = async {
        let recall = evidence(&role.pool, &capabilities, &fixture.installed.scope).await;
        let answer = recall
            .search(COMMIT_WORD, Some(query_vector(COMMIT_WORD)), 10)
            .await?;
        let body = recall.get(answer.hits[0].id).await?;
        let status = recall.status().await?;
        let absent = recall.search(NONSENSE, None, 10).await?;
        ostk_fleet_recall::Result::Ok((answer, body, status, absent))
    }
    .await;
    role.drop_role(&owner).await;
    let (answer, body, status, absent) = reads.expect("the runtime grants cover every read");
    assert_eq!(answer.absence.verdict, AbsenceVerdictV1::Present);
    assert!(body.is_some());
    assert!(!status.sources.active.is_empty());
    assert_absent(&absent);
}

/// The serving process's query model in the MCP proof: the stub's model id,
/// but every query embeds to the first unit vector. A stub body vector is a
/// hash expanded to 512 components of magnitude at most 127.5, so its cosine
/// with that unit vector is far below the dense floor: the dense lane runs on
/// every search and never clears the floor. Every hit is then a lexical one,
/// and whether an empty answer is absent or unknown is decided by the verdict
/// alone, not by which stub vectors happen to be near.
struct FarQueryEmbedder;

impl ChunkEmbedder for FarQueryEmbedder {
    fn dim(&self) -> usize {
        StubEmbedder.dim()
    }

    fn model_id(&self) -> &'static str {
        StubEmbedder.model_id()
    }

    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts
            .iter()
            .map(|_| {
                let mut vector = vec![0.0; self.dim()];
                vector[0] = 1.0;
                vector
            })
            .collect()
    }
}

/// `serve`'s MCP server for `scope` over `pool`, composed as
/// `build_memory_service` composes a record-only writer: evidence recall is
/// attached exactly when `start_evidence_recall` serves it for this login,
/// under the stub model's digest. The scope's corpus model is registered, as
/// deployment bootstrap registers it, so chunk search answers too.
async fn serve_as_main(
    owner: &PgPool,
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
    embedder: Arc<dyn ChunkEmbedder>,
) -> (McpServer, bool) {
    CockroachStore::from_pool(owner.clone(), scope.clone())
        .expect("a valid store scope")
        .initialize_embedding_model(embedder.model_id())
        .await
        .expect("register the corpus model");
    let ledger = CockroachClaimLedger::new(
        pool.clone(),
        scope.clone(),
        embedder.clone(),
        retry_policy(),
    )
    .expect("claim ledger");
    let evidence = start_evidence_recall(
        pool,
        capabilities,
        scope,
        &Sha256Digest::from_bytes(STUB_MODEL_DIGEST).to_hex(),
    )
    .await;
    let served = evidence.is_some();
    let mut service = CockroachMemoryService::new(
        scope.clone(),
        Arc::new(CockroachStore::from_pool(pool.clone(), scope.clone()).expect("store scope")),
        Arc::new(ledger),
        embedder,
    )
    .expect("memory service");
    if let Some(evidence) = evidence {
        service = service.with_evidence_recall(evidence);
    }
    (
        McpServer::new(Arc::new(service), scope.clone()).expect("MCP server"),
        served,
    )
}

/// One MCP session over an in-memory duplex: each request is one line in and
/// its response one line out, through the server's real newline framing.
struct McpSession {
    writer: WriteHalf<DuplexStream>,
    lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
    task: JoinHandle<std::io::Result<()>>,
    next_id: u64,
}

impl McpSession {
    fn open(server: McpServer) -> Self {
        let (client, server_side) = tokio::io::duplex(4 << 20);
        let (server_reader, server_writer) = tokio::io::split(server_side);
        let task = tokio::spawn(async move { server.serve(server_reader, server_writer).await });
        let (reader, writer) = tokio::io::split(client);
        Self {
            writer,
            lines: BufReader::new(reader).lines(),
            task,
            next_id: 0,
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let mut request = json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method });
        if !params.is_null() {
            request["params"] = params;
        }
        self.writer
            .write_all(format!("{request}\n").as_bytes())
            .await
            .expect("the server reads the request");
        let line = self
            .lines
            .next_line()
            .await
            .expect("the server answers")
            .expect("one response line per request");
        let response: Value = serde_json::from_str(&line).expect("the response is JSON");
        assert_eq!(response["id"], self.next_id, "{response}");
        response
    }

    async fn tools(&mut self) -> Value {
        self.request("tools/list", Value::Null).await["result"]["tools"].clone()
    }

    /// `recall`'s structured content, or the JSON-RPC error of a refused
    /// request.
    async fn recall(&mut self, arguments: Value) -> Result<Value, Value> {
        let response = self
            .request(
                "tools/call",
                json!({ "name": "recall", "arguments": arguments }),
            )
            .await;
        if let Some(error) = response.get("error") {
            return Err(error.clone());
        }
        let result = &response["result"];
        assert_eq!(result["isError"], false, "{}", result["content"][0]["text"]);
        Ok(result["structuredContent"].clone())
    }

    async fn recall_ok(&mut self, arguments: Value) -> Value {
        let context = arguments.to_string();
        self.recall(arguments)
            .await
            .unwrap_or_else(|error| panic!("{context}: {error}"))
    }

    async fn close(mut self) {
        self.writer.shutdown().await.expect("close the client side");
        self.task
            .await
            .expect("the server task finishes")
            .expect("the server ends cleanly at end of input");
    }
}

fn warning_codes(content: &Value) -> Vec<String> {
    content["warnings"]
        .as_array()
        .expect("warnings are an array")
        .iter()
        .map(|warning| warning["code"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one MCP session from tools/list through status
async fn live_serve_recall_evidence_end_to_end_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let fixture = WorkerFixture::install(&pool, "evidence-serve").await;
    tick(&fixture, &pool, "all").await;
    let scope = &fixture.installed.scope;
    let (server, evidence_served) = serve_as_main(
        &pool,
        &pool,
        &capabilities,
        scope,
        Arc::new(FarQueryEmbedder),
    )
    .await;
    assert!(
        evidence_served,
        "a login that reads the Stage-5 tables serves evidence"
    );
    let mut session = McpSession::open(server);

    // tools/list advertises kind=evidence beside the record-only remember.
    let tools = session.tools().await;
    let expected = tool_list_for_surfaces(
        RememberSurface::RECORD_ONLY,
        RecallSurface {
            evidence: true,
            ..RecallSurface::NONE
        },
    );
    assert_eq!(tools, json!(expected));
    assert_eq!(tools[1], tool_list()[1], "remember is unchanged");
    assert!(
        tools[0]["inputSchema"]["properties"]["kind"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("evidence"))
    );

    // Search embeds the query for the dense lane and finds the commit
    // lexically; get returns its full text by the hit's id.
    let found = session
        .recall_ok(json!({ "action": "search", "kind": "evidence", "query": COMMIT_WORD }))
        .await;
    assert_eq!(found["tool"], "recall");
    assert_eq!(found["data"]["absence"]["verdict"], "present");
    assert_eq!(found["data"]["readiness"]["dense_lane"], "used");
    assert!(
        found["data"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .all(|hit| hit["matched_by"] == "lexical"),
        "{found}"
    );
    assert_eq!(found["conflict_coverage"]["status"], "not_evaluated");
    let retrieval = &found["diagnostics"]["retrieval"];
    assert_eq!(retrieval["tier"], "evidence");
    assert_eq!(retrieval["lanes"], json!(["lexical", "dense"]));
    assert!(
        found["data"]["sources"]["active"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["connector_instance"] == GIT_INSTANCE)
    );
    let mut commit = None;
    for hit in found["data"]["hits"].as_array().unwrap() {
        let body = session
            .recall_ok(json!({ "action": "get", "kind": "evidence", "id": hit["id"] }))
            .await;
        let body = &body["data"]["evidence"];
        assert_eq!(body["id"], hit["id"]);
        assert_eq!(
            body["first_accepted_event_id"],
            hit["first_accepted_event_id"]
        );
        if body["text"].as_str().unwrap().contains(COMMIT_WORD) {
            commit = Some(body.clone());
        }
    }
    let commit = commit.expect("a hit's full text carries the commit word");
    assert!(!commit["media_type"].as_str().unwrap().is_empty());
    let missing = session
        .recall_ok(json!({ "action": "get", "kind": "evidence", "id": "42".repeat(32) }))
        .await;
    assert!(missing["data"]["evidence"].is_null());

    // Nothing matches a nonsense query over a current, covered, fresh scope.
    let absent = session
        .recall_ok(json!({ "action": "search", "kind": "evidence", "query": NONSENSE, "limit": 5 }))
        .await;
    assert_eq!(absent["data"]["hits"], json!([]));
    assert_eq!(absent["data"]["absence"]["verdict"], "absent", "{absent}");
    assert!(warning_codes(&absent).is_empty(), "{absent}");

    // Chunk-only filters are refused as invalid parameters.
    let refused = session
        .recall(json!({
            "action": "search", "kind": "evidence", "query": COMMIT_WORD, "min_score": 0.2
        }))
        .await
        .expect_err("min_score is not an evidence filter");
    assert_eq!(refused["code"], -32602);
    assert!(
        refused["message"]
            .as_str()
            .unwrap()
            .contains("evidence search does not support"),
        "{refused}"
    );

    // Status reports readiness and every source.
    let status = session.recall_ok(json!({ "action": "status" })).await;
    let evidence = &status["data"]["evidence"];
    assert_eq!(evidence["served"], true);
    assert_eq!(evidence["readiness"]["lexical_current"], true);
    assert!(
        evidence["sources"]["active"]
            .as_array()
            .unwrap()
            .iter()
            .all(|source| source["last_outcome"] == "ok" && source["stale"] == false),
        "{evidence}"
    );

    // Chunk search still answers from the corpus, not the evidence tiers.
    let chunks = session
        .recall_ok(json!({ "action": "search", "query": COMMIT_WORD }))
        .await;
    assert_eq!(chunks["diagnostics"]["retrieval"]["fusion"], "rrf");
    assert!(chunks["data"].get("absence").is_none());

    // A stale source turns an empty answer unknown, and the answer says which
    // source and why.
    sqlx::query(
        "UPDATE memory_worker_sources_v1 \
         SET last_checked_at = last_checked_at - INTERVAL '2 days' \
         WHERE tenant_id = $1 AND project = $2 AND connector_instance_id = $3",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(GIT_INSTANCE)
    .execute(&pool)
    .await
    .unwrap();
    let stale = session
        .recall_ok(json!({ "action": "search", "kind": "evidence", "query": NONSENSE }))
        .await;
    assert_eq!(stale["data"]["absence"]["verdict"], "unknown");
    assert_eq!(stale["data"]["absence"]["reasons"], json!(["source_stale"]));
    assert_eq!(warning_codes(&stale), ["evidence_source_stale"]);
    assert_eq!(
        stale["warnings"][0]["connector_instances"],
        json!([GIT_INSTANCE])
    );
    session.close().await;
}

#[tokio::test]
async fn live_serve_without_grants_keeps_tools_byte_identical_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let scope = common::fresh_scope("evidence-serve-ungranted");
    // The runtime login as it was before the Stage-5 block: the evidence
    // and claim planes, nothing Stage-5 reads.
    let role = RuntimeProbeRole::create_claim_writer(&owner, &database_url).await;
    let (server, evidence_served) = serve_as_main(
        &owner,
        &role.pool,
        &capabilities,
        &scope,
        Arc::new(StubEmbedder),
    )
    .await;
    let mut session = McpSession::open(server);
    let tools = session.tools().await;
    let search = session
        .recall(json!({ "action": "search", "kind": "evidence", "query": COMMIT_WORD }))
        .await;
    let get = session
        .recall(json!({ "action": "get", "kind": "evidence", "id": "42".repeat(32) }))
        .await;
    let status = session.recall(json!({ "action": "status" })).await;
    session.close().await;
    role.drop_role(&owner).await;

    assert!(
        !evidence_served,
        "a login without the Stage-5 grants serves no evidence"
    );
    assert_eq!(tools, json!(tool_list()));
    assert_eq!(
        serde_json::to_vec(&tools).unwrap(),
        serde_json::to_vec(&tool_list()).unwrap()
    );
    let search = search.expect_err("kind=evidence is not served");
    assert_eq!(
        search["message"],
        "recall search kind \"evidence\" is not supported; use chunk or claim"
    );
    let get = get.expect_err("kind=evidence is not served");
    assert_eq!(
        get["message"],
        "recall get kind \"evidence\" is not supported"
    );
    let status = status.expect("status answers");
    assert!(status["data"].get("evidence").is_none(), "{status}");
}
