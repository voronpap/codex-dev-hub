# Ledger identity

The DevFabric resource ledger is a durable authority, not a cache. Its filesystem
path says where SQLite is stored; it does not establish which accounting authority
the file represents. Normal runtime startup opens only a ledger whose immutable
identity exactly matches trusted host configuration.

## Identity model

`LedgerIdentityCoreV1` is the equality and qualification boundary:

| Field | Meaning |
| --- | --- |
| `family` | Fixed `devfabric_resource_ledger` family marker |
| `format_version` | Identity format version, currently `1` |
| `instance_id` | Opaque 128-bit lowercase hexadecimal identifier generated once |
| `authority_scope_kind` | `project` for normal use or `qualification` for a future reviewed qualification |
| `authority_scope_id` | Stable host-owned logical authority identifier |
| `account_binding_hash` | Optional stable account-authority digest; null when none exists |

For normal project-scoped configuration, `authority_scope_id` must equal the trusted
configured project. It is not copied from an MCP request. A later Stage 3G
qualification may provide `authority_scope_kind=qualification` and a stable,
qualification-bound authority ID shared by its paired sessions. This document does
not define or implement `QualificationManifestV2`.

`LedgerIdentityMetadataV1` stores UTC `created_at` and `created_by_runtime` for
audit. Metadata is immutable but is deliberately excluded from reopen equality, so
a runtime upgrade does not invalidate a correct ledger.

The identity digest is SHA-256 over UTF-8 JSON containing the core fields only,
with keys sorted, no insignificant whitespace, and JSON primitives emitted by the
strict Pydantic model. Paths, timestamps, process IDs, hostnames, metadata and
secrets are excluded.

SQLite `PRAGMA application_id` is `1145459276` (`0x4446524C`, header bytes
`44 46 52 4c`, ASCII `DFRL`). This identifies the database family at the SQLite
header level. It does not replace the logical identity row.

## Explicit initialization and normal startup

Generate a fresh opaque `instance_id` once, add the reviewed identity to the trusted
delegation config, then explicitly initialize the ledger:

```sh
uv run --locked python -m devhub.delegate_server \
  --config .devhub/local.json --initialize-ledger
```

This command initializes or validates the configured ledger and exits without
starting MCP or contacting a provider. Normal startup never initializes missing
authority:

```sh
uv run --locked python -m devhub.delegate_server --config .devhub/local.json
```

Changing `state_root` therefore fails normal startup until a separate explicit
initialization decision is made. Initialization is not a reset command. Operators
must not reuse an existing `instance_id` to create a replacement ledger or discard
replay, unknown-usage, live-slot, event or grant history. No destructive reset CLI
exists.

## Bootstrap classification and migration order

Before domain migration, DevFabric reads `application_id`, `user_version`,
`sqlite_master`, identity-table presence and the exact domain-schema fingerprint.
It classifies the database as one of:

- `NEW_EMPTY`: application and schema versions are zero and there are no user objects.
- `VALID_IDENTIFIED_DEVFABRIC`: application ID, table/triggers, single identity row,
  metadata, canonical digest and trusted expected core all validate.
- `LEGACY_UNIDENTIFIED_DEVFABRIC`: an exact repository-known pre-identity schema is
  present without identity.
- `FOREIGN_NONEMPTY`: a non-empty database is not a recognized DevFabric ledger.
- `IDENTITY_MISMATCH`: a claimed identity is unsupported, inconsistent or different
  from trusted host authority.

For `NEW_EMPTY`, one exclusive transaction sets the application ID, creates the
single-row identity table, inserts and verifies identity and metadata, and installs
triggers that reject update/delete. That transaction commits before domain
migrations start. Migration failure can therefore leave an identified version-zero
ledger, but it cannot leave partially migrated domain tables.

For an existing ledger, identity validation happens before any migration statement.
Wrong identity, foreign storage and legacy-unclaimed storage fail without domain
schema mutation. Identity `format_version` is independent of SQLite
`PRAGMA user_version`, which remains the domain migration version.

## Recognized legacy fingerprints

The normal runtime recognizes, but does not adopt, exact schemas produced by domain
migration levels 1 through 6. Fingerprints are SHA-256 over canonical ordered
`sqlite_master` entries (type, name, owning table and normalized SQL), excluding
SQLite internal and identity objects:

| Fingerprint ID | SHA-256 |
| --- | --- |
| `devfabric-domain-v1` | `b2bc96fa31b48c6e2225c608d127e39feb2162eb37917278bf185078c8696639` |
| `devfabric-domain-v2` | `afd91302e06a9c3ce90e4253f635f14344eecdefc71f612142f6556ed8c40c0b` |
| `devfabric-domain-v3` | `06588c1c404505bbb2cae1c7583535e0c0874bb6888270ac8ed6ef9eed5b758b` |
| `devfabric-domain-v4` | `57d2346be790a56b2ce4d61797ef3bd6cb827f1ac19ed72cc6380faa2a55cf75` |
| `devfabric-domain-v5` | `35bd9d59d04d8aa359d179182a1036aea0c91e903f729e87549d88cc5646fe97` |
| `devfabric-domain-v6` | `fa1a7bf67a70eb64d4fcfcd2cd1d167694739efbba07637ac3a21e7cd8875cc2` |

A loose marker such as a `reservations` table is insufficient. Normal opening of
any recognized legacy database raises `LEGACY_IDENTITY_REQUIRED` and does not add
identity or run migrations.

## Legacy adoption boundary

No adoption operation is implemented in this change. A future reviewed operation
must require an exact fingerprint, durable backup, operator-supplied expected core,
an unresolved-liability check, pre-adoption database hash and schema fingerprint,
one identity-installation transaction, and a post-adoption receipt. Opening a path
is never adoption.

## State-root protection

The ledger must be a direct regular-file child of an existing absolute state root.
The stdlib checks reject a symlinked root, a symlinked ledger, resolved-path escape,
and Windows paths whose available stat metadata reports a reparse point. The checks
run before opening and again after SQLite connects; identity is also revalidated for
every new application transaction.

These checks do not create a universal filesystem sandbox. A privileged actor can
race path inspection or replace storage outside DevFabric, Windows reparse reporting
varies by filesystem, and an exact byte-for-byte database clone carries the same
logical identity. Deployment must protect the state directory with OS permissions;
strong handle-relative/open-by-ID protection would require a separately reviewed
platform-specific implementation.

## Stable errors

Bootstrap failures expose non-sensitive codes: `FOREIGN_DATABASE`,
`LEGACY_IDENTITY_REQUIRED`, `LEDGER_IDENTITY_MISMATCH`,
`UNSUPPORTED_LEDGER_IDENTITY_VERSION`, `UNSUPPORTED_LEDGER_SCHEMA_VERSION`,
`UNSUPPORTED_LEDGER_JOURNAL`, `UNSAFE_STATE_ROOT`, and
`IDENTITY_BOOTSTRAP_FAILURE`. Messages do not include identity values, account
bindings or host paths.
