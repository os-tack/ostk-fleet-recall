//! Bounded additional trust roots for the remote clients. System/built-in
//! roots remain enabled; neither redirects nor hostname verification changes.

use std::{fs::File, io::Read as _, path::Path};

use reqwest::{Certificate, Client, ClientBuilder};
use rustix::fs::{Mode, OFlags};

use crate::{FleetError, Result};

const MAX_CA_BYTES: usize = 262_144;
const MAX_CA_CERTIFICATES: usize = 256;

fn invalid(message: &str) -> FleetError {
    FleetError::Configuration(message.into())
}

/// Read and validate a certificates-only PEM bundle.
///
/// Follow operator-owned
/// symlinks (including projected Kubernetes volumes), then check the opened
/// descriptor so a FIFO/device or concurrently grown file cannot block startup.
pub fn read_ca_bundle(path: &Path) -> Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| invalid("cannot open client CA bundle"))?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| invalid("cannot inspect client CA bundle"))?;
    if !metadata.is_file() || metadata.len() > MAX_CA_BYTES as u64 {
        return Err(invalid(
            "client CA bundle must be a regular file of at most 256 KiB",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("cannot read client CA bundle"))?;
    // Building a client checks the DER trust anchors too: reqwest's PEM parser
    // alone accepts decoded bytes that are not an X.509 certificate.
    with_ca_pem(Client::builder().no_proxy(), &bytes)?
        .build()
        .map_err(|_| invalid("invalid certificate in client CA bundle"))?;
    Ok(bytes)
}

/// Add an optional public CA bundle without disabling the default roots.
pub fn with_ca_bundle(builder: ClientBuilder, path: Option<&Path>) -> Result<ClientBuilder> {
    if let Some(path) = path {
        with_ca_pem(builder, &read_ca_bundle(path)?)
    } else {
        Ok(builder)
    }
}

/// Add already bounded, certificates-only PEM data to a client builder.
pub(crate) fn with_ca_pem(mut builder: ClientBuilder, bytes: &[u8]) -> Result<ClientBuilder> {
    if bytes.is_empty() || bytes.len() > MAX_CA_BYTES {
        return Err(invalid(
            "client CA bundle must contain 1..=256 KiB of certificate PEM",
        ));
    }
    let mut remaining = std::str::from_utf8(bytes)
        .map_err(|_| invalid("client CA bundle must contain only certificate PEM"))?
        .trim_ascii();
    let mut count = 0;
    while !remaining.is_empty() {
        let body = remaining
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .ok_or_else(|| invalid("client CA bundle must contain only certificate PEM"))?;
        let (encoded, rest) = body
            .split_once("-----END CERTIFICATE-----")
            .ok_or_else(|| invalid("unterminated certificate in client CA bundle"))?;
        if encoded.trim_ascii().is_empty()
            || !encoded.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || byte.is_ascii_whitespace()
                    || matches!(byte, b'+' | b'/' | b'=')
            })
        {
            return Err(invalid("invalid certificate PEM in client CA bundle"));
        }
        count += 1;
        if count > MAX_CA_CERTIFICATES {
            return Err(invalid(
                "client CA bundle contains more than 256 certificates",
            ));
        }
        remaining = rest.trim_ascii();
    }
    let certificates = Certificate::from_pem_bundle(bytes)
        .map_err(|_| invalid("invalid certificate PEM in client CA bundle"))?;
    if count == 0 || certificates.len() != count {
        return Err(invalid(
            "client CA bundle contains no complete certificates",
        ));
    }
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    Ok(builder)
}

#[cfg(test)]
pub(crate) mod tests;
