-- Carry typed conflict state onto semantically retrieved source evidence.
--
-- The public hybrid lane returns bounded memory_chunks IDs. Claims may cite
-- those exact chunks through memory_claim_support; this index makes resolving
-- the corresponding claim IDs a project-scoped point lookup instead of a
-- support-table scan.
CREATE INDEX memory_claim_support_chunk_idx
    ON memory_claim_support (tenant_id, project, chunk_id, state, claim_id);
