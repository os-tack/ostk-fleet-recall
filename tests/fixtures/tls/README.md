# Public TLS test fixtures

These certificates and server private keys were generated exclusively for
automated tests. They are public test data, not credentials for any deployment.
Never install these trust roots or use these keys outside tests.

`ca-first.pem` and `ca-second.pem` are independent roots. Each signs the
corresponding `server-*.pem`, whose SAN is only `localhost`. The second pair
tests overlapping trust during CA rotation. `server-expired.pem` uses the
first server key but is already expired. Valid fixtures expire in 2036.

The roots and server keys were generated with OpenSSL RSA-2048/SHA-256.
Root private keys and CSRs are not included. Server keys use unencrypted
PKCS#8 PEM so the test TLS server can load them without external tooling.
