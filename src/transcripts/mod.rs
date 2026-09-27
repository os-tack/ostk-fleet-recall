//! Scoped transcript spool transport. Raw bytes stay outside the ledger until
//! the existing worker redacts, canonicalizes and admits them.
mod receiver;
mod shipper;
pub use receiver::{
    MAX_WINDOW_BYTES, TranscriptAuthorization, TranscriptError, TranscriptProgress,
    TranscriptReceiver, TranscriptReceiverConfig, TranscriptUpload, scope_spool_dir,
    stable_file_name,
};
pub use shipper::{ShipReport, ShipperConfig, ship_once, ship_transcripts};
#[cfg(test)]
mod tests;
