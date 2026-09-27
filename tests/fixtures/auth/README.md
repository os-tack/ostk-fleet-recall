# Authentication test fixtures

`rsa-private.der` is a newly generated, public test-only 2048-bit RSA private key in PKCS#1 DER form. Never use it outside tests. `rsa-public.json` is its RS256 verification JWK. Tests generate ES256 keys with ring and use deterministic Ed25519 test seeds.
