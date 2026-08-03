# BitBackup `bbk/1` format specification (draft)

Status: **draft, not frozen, not independently audited**. This document describes the
byte-level format implemented by `bbcore` at format version 1 and suite 1. In case of a
disagreement, the disagreement is a format bug; neither the implementation nor this draft
silently takes precedence. No valuable data should be committed to this format yet.

Normative words MUST, MUST NOT, SHOULD and MAY have their usual RFC 2119 meanings. Byte
strings are concatenated with `||`. Integers outside CBOR are unsigned big-endian. Labels
contain exactly the shown ASCII bytes and no terminating NUL.

## Algorithms and identifiers

Format version is 1. Suite 1 uses ML-KEM-1024, X25519, SHAKE256, BLAKE3 and
AES-256-GCM-SIV. Hashes, file keys and identity identifiers are 32 bytes; AEAD nonces are
12 bytes and tags are 16 bytes. The Reed-Solomon field is GF(2^8), so `data + parity`
MUST NOT exceed 255. The currently registered RS profile is 8+3.

The hybrid construction is project-specific and MUST NOT be represented as a standardized
KEM combiner. It requires independent cryptographic review before format freeze.

## Object name

An object is stored as:

```text
base32_lower_no_padding(identity_id) "."
base32_lower_no_padding(object_name) ".bbk"
```

Both binary fields are 32 bytes and therefore encode to 52 characters. `object_name` for
canonical index `i` is the first 32 output bytes of:

```text
SHAKE256(K_file || "bbk/1/name" || u32be(i))
```

Canonical index is:

```text
i = stripe * (rs_data + rs_parity) + position
```

Data positions are `0 .. rs_data-1`; parity positions are
`rs_data .. rs_data+rs_parity-1`. Missing data positions in the final partial stripe do
not produce objects. Parity positions do not move in a partial stripe.

## Container layout

There is no plaintext header. A suite-1 object is:

| Offset | Length | Value |
|---:|---:|---|
| 0 | 1568 | ML-KEM-1024 ciphertext |
| 1568 | 32 | ephemeral X25519 public key |
| 1600 | 80 | encrypted `K_file || file_id` including AEAD tag |
| 1680 | `C + 16` | encrypted metadata including AEAD tag |
| `1696 + C` | derived | shard core |
| end | metadata `pad` | random padding |

`C` is exactly 4096, 8192 or 16384. A reader tries the supported classes and accepts only
an authenticating, canonical metadata value. The full storage object size is required to
derive the shard-core length. Random tail padding MUST be removed according to authenticated
metadata and MUST NOT overlap the shard core.

## File and processing identities

`file_instance_id` identifies a logical watched path independently of its current physical
source location:

```text
BLAKE3-keyed(k_instance,
  "bbk/1/file-instance" ||
  u32be(len(root_label)) || root_label ||
  u32be(len(relative_path)) || relative_path)
```

Both strings are strict UTF-8. `root_label` is one nonempty component. `relative_path` uses
`/`, is nonempty and contains no empty, `.` or `..` components.

The canonical processing profile byte string is:

```text
"bbk/1/processing" ||
u16be(profile_version) || transform_id(4) ||
u32be(split_min) || u32be(split_avg) || u32be(split_max) || u32be(split_align) ||
u16be(rs_data) || u16be(rs_parity) || u8(pad_shards) ||
u16be(metadata_schema) || u16be(shard_codec) || u16be(rs_codec)
```

Suite 1 registers profile version, metadata schema, shard codec and RS codec as 1.
`processing_id = BLAKE3(canonical_processing_profile)`.

```text
file_id = BLAKE3-keyed(k_fileid,
  "bbk/1/file-id" || file_instance_id || content_hash || processing_id)
```

Thus changing compression/transform, split geometry, RS geometry, padding policy or any
codec/schema version changes `file_id`, `K_file` and every object name.

## Hybrid envelope

For any byte string `x`:

```text
encode(x) = u32be(len(x)) || x
```

The combiner transcript is:

```text
encode("bbk/1/kem")
|| u16be(format_version) || u16be(suite_id)
|| encode(identity_id)
|| encode(pk_mlkem) || encode(pk_x25519)
|| encode(ct_mlkem) || encode(epk_x25519)
```

The input is `encode(ss_mlkem) || encode(ss_x25519) || transcript`. The first 44 bytes of
SHAKE256 output are `K_env || N_env` (32 and 12 bytes). AES-256-GCM-SIV encrypts the
64-byte plaintext `K_file || file_id`; its AAD is the transcript. The resulting 80 bytes
are stored at offset 1600.

## Metadata encryption

For canonical index `i`, metadata key material is derived by the suite-1 key schedule using
the domain `bbk/1/meta` and `u32be(i)`, producing a 32-byte key followed by a 12-byte nonce.
The exact key-schedule construction and all remaining derivations MUST be added here with
golden vectors before format freeze.

Metadata AAD is:

```text
"bbk/1/meta-aad" || identity_id || object_name || u32be(C + 16)
```

`object_name` here is the raw 32-byte component, not its base32 representation.

## Metadata plaintext and CBOR schema

Metadata plaintext is exactly `C` bytes:

```text
u32be(cbor_length) || canonical_cbor || zero padding to C
```

The decoder MUST reject non-minimal integers, indefinite lengths, tags, floats, duplicate
or out-of-order keys, unknown or missing fields, trailing CBOR bytes and nonzero class
padding. Text MUST be strict UTF-8 without embedded NUL.

The canonical CBOR map is:

```text
{
  "v": uint,
  "rs": {"data": uint, "chunks": uint, "parity": uint},
  "pad": uint,
  "file": {
    "hash": bstr(32), "name": tstr, "path": tstr, "size": uint,
    "created": int, "instance": bstr(32), "modified": int,
    "attributes": uint
  },
  "self": {"index": uint, "stripe": uint, "position": uint},
  "split": {"avg": uint, "max": uint, "min": uint, "align": uint},
  "merkle": {"path": [bstr(32), ...], "root": bstr(32)},
  "stream": {"transform": bstr(4), "stored_size": uint}
}
```

Keys are encoded in RFC 8949 deterministic order: first by encoded length, then
bytewise. The displayed map is already in that order at each level.

`path` MUST be a nonempty relative path using `/`. Empty components, `.`, `..`, `\\`,
absolute paths, drive paths and UNC paths are forbidden. A restore implementation MUST
also resolve against its destination root and reject symlink/reparse-point escapes at write
time. `name` MUST be a single nonempty component.

The decoder MUST prove that `chunks` corresponds to some fragment count under the stated
RS parameters, that `self.stripe` exists, and that `self.position` exists in that stripe.

## Merkle and Reed-Solomon

For each data position, the suite-1 key schedule derives `K_shard` and `N_shard` from
`K_file`, the stripe number and the position. AES-256-GCM-SIV encrypts the fragment with:

```text
"bbk/1/shard-aad" || identity_id || file_id ||
u32be(stripe) || u16be(position) || u32be(fragment_length)
```

The resulting `fragment_length + 16` bytes are the data shard core. Reed-Solomon is then
applied systematically to the complete encrypted data shard cores, including their AEAD
tags. Parity shard cores are the resulting parity symbols and receive no second AEAD layer.
After reconstruction, every recovered data core MUST pass its AEAD verification before its
plaintext is released.

Merkle leaves are all data and parity shard cores in ascending canonical-index order. A lone
odd node is promoted unchanged. Internal nodes and leaf hashing use the suite-1 domains
implemented by the key schedule. Reed-Solomon uses GF(2^8) and a systematic Cauchy matrix;
the final stripe uses its actual data count while retaining registered parity positions.

The precise field polynomial and matrix formula remain an **unresolved normative section**.
Golden complete-container vectors are also required. Until these are written and
independently reproduced, `bbk/1` MUST remain draft.

## Local identity state (not a `.bbk` object)

Local application state uses a separate authenticated envelope and is not part of the
backup-container format. Its header is `"bbk1st" || version(1) || reserved(0) ||
identity_id(32) || nonce(12)`. The state key is the first 32 bytes of
`SHAKE256(k_instance || "bbk/1/state-key")`. AES-256-GCM-SIV authenticates the complete
52-byte header as AAD and appends a 16-byte tag to the encrypted state. The nonce is fresh
random data for every save. Public-only identities MUST NOT seal or open local state.
