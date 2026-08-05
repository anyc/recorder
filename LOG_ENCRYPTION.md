# Log encryption

Recorder encrypts segment frame payloads while leaving segment metadata
available for discovery and retention. Configuration affects newly opened
segments only.

## Cryptographic construction

Each encrypted segment has an independent random 32-byte data-encryption key
(DEK). The DEK is wrapped for the recipient with RSA-OAEP using SHA-256 for
both OAEP and MGF1.

Compression happens before encryption. Stored frame data is encrypted with
AES-256-GCM. Each segment receives a random four-byte nonce prefix, and frame
`n` uses:

```text
nonce = nonce_prefix || big_endian_uint64(n)
```

The plaintext frame header is authenticated as GCM additional authenticated
data. Each encrypted frame stores its GCM tag. The existing frame CRC still
protects accidental corruption, but is not a substitute for GCM
authentication.

## Segment layout

An encrypted segment contains:

```text
fixed segment header
RECENC01 encryption extension
dictionary bytes, if configured
encrypted frames
plaintext segment footer
```

The `RECENC01` extension records the format version, algorithm identifiers,
nonce-prefix length, and wrapped DEK. It never contains the private key or
plaintext log messages.

The following remain plaintext by design:

- boot ID and boot sequence;
- segment sequence;
- timezone and timestamps in the segment header/footer;
- frame offsets, lengths, and flags;
- index metadata.

Indexes contain timing, priority, frame, and service-hash metadata, but no
message bodies. Encryption protects log payloads, not all metadata or traffic
analysis.

## Configuration and use

Configure the recorder with a readable PEM RSA public key:

```json
{
  "encryption_public_key": "/etc/recorder/encryption-public.pem"
}
```

The recorder needs only the public key. Keep the corresponding private key
outside the recorder process and protect it separately. To read encrypted
segments, give the player the private-key PEM:

```sh
player -D /var/log/recorder \
  --encryption-private-key /secure/keys/encryption-private.pem
```

The library equivalent is `rec_player_set_private_key()`. Metadata-only
operations can inspect encrypted segments without a private key; payload
scans fail unless the matching private key is configured.

## Key rotation and failure behavior

The recorder generates a fresh DEK and nonce prefix for every segment. The RSA
recipient key can be changed for future segments without re-encrypting old
segments. Old segments remain readable only with the private key corresponding
to their wrapped DEK.

Authentication failures, wrong or missing keys, tampered tags, nonce/frame
inconsistencies, and invalid decrypted payloads cause encrypted payload scans
to fail. Metadata-only scans do not attempt decryption.

## Indexes and recovery

Indexes are written incrementally while a segment is active. The recorder can
construct index rows from the plaintext chunk before encrypting the frame, so
the private key is not needed during recording. Index files are advisory and
are not forced to storage; the segment remains the source of truth after a
crash.

An active index has a valid header and complete rows up to its last successful
append. A cleanly closed index receives a footer containing its final row count
and segment committed end. Index reader/player support is planned separately.

## Security boundaries and limitations

- RSA keys must be managed and permissioned by the deployment; the recorder
  does not encrypt or protect the private key.
- Plaintext metadata and indexes can reveal when, how often, and which service
  emitted logs.
- Anyone with the private key can decrypt the messages; signatures are not
  currently implemented.
- The current encryption extension supports RSA recipient keys.

