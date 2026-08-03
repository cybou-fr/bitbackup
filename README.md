# BitBackup

Cross-platform client for encrypted backup and file transfer.

A file is split into chunks of pseudorandom size. Each chunk is encrypted and becomes a
self-contained object. Reed–Solomon adds redundancy. There are no manifest files, no server
indexes, no required database — **any surviving chunk lets you derive the names of all the
others and reconstruct the whole file.**

The storage stays dumb. It only stores, returns, checks existence, and lists objects. All
cryptography and all logic live in the client.

## Properties

* **Post-quantum first.** Hybrid ML-KEM-1024 + X25519 is designed to retain confidentiality
  while at least one component remains secure. The custom combiner has not been independently audited.
* **Encrypted identity state.** Private configuration is sealed by `bbcore` with a key
  derived from the unlocked identity; the UI never receives the raw state key. Legacy
  DPAPI configuration is migrated after the first successful mnemonic unlock.
* **Only chunks in the storage.** A folder or a bucket holding encrypted objects, nothing
  else — no manifests, no indexes, no marker files.
* **Metadata-hiding storage.** File content, names, paths and authenticated logical layout
  are encrypted. Storage can still infer approximate relationships from identity prefixes,
  object sizes, upload timing, and network or account metadata.
* **Restore from a single chunk.** No catalog, no database, no access to the original
  storage required — your mnemonic and any one `.bbk` file are enough.
* **Damage tolerance.** Reed–Solomon 8+3 survives the loss of any three elements of every
  stripe.
* **Multiple identities from one mnemonic**, or from independent mnemonics. The provider
  cannot tell that two identities belong to the same person.
* **Any storage.** Local folder, USB, S3 and S3-compatible, SFTP, FTPS, FTP. The same object
  can live in all of them at once.

## How it works

```text
file
  → BLAKE3 of the whole file
  → derive the file key
  → optional whole-stream compression
  → deterministic pseudorandom split
  → encrypt each fragment
  → group into Reed–Solomon stripes, compute parity
  → build a Merkle tree over all shards
  → derive every object name from the file key
  → seal a fresh hybrid KEM envelope into each chunk
  → upload
```

Every chunk carries the same encrypted metadata: file name, path, size, BLAKE3 of the
original, Reed–Solomon parameters, the Merkle root, and its own position. Object names are
derived from the file key rather than hashed from content, which is what makes one chunk
sufficient to locate all the others.

Restoring reverses the pipeline and verifies the result against the original BLAKE3.

## Status

Early development. The `bbk/1` container format is under active design; the core is
partially implemented and must not yet be used for valuable data.

The tracked [FORMAT.md](FORMAT.md) is the normative draft and explicitly lists the sections
that must be completed before the format can be frozen.

| Component | State |
|---|---|
| Format specification | in progress; normative public specification not yet published |
| Library C ABI | declared |
| base32, object names | implemented, tested |
| SHAKE256 (KDF/XOF) | implemented, tested against FIPS 202 vectors |
| ML-KEM-1024 | implemented, deterministic keygen from seed verified |
| X25519 | implemented, tested against RFC 7748 vectors |
| BLAKE3 | implemented, tested against the official vectors |
| Identity derivation, BIP39 | implemented, tested against the official vectors |
| AES-256-GCM-SIV | implemented, tested against RFC 8452 |
| ML-DSA-87 signatures | not started, needed only for transfers |
| Hybrid KEM combiner | implemented, golden vectors frozen, **not yet audited** |
| Splitter, Merkle, CBOR metadata | implemented, tested |
| File instance, processing profile and file ID derivation | implemented, golden vectors |
| Compression (zstd) | not started |
| Reed–Solomon | implemented, fuzzed over 10 000 stripes |
| Storage backends | not started |
| Storage indexing | not started |
| C++Builder UI | screens exist, core not wired in |

## Layout

```text
bbcore/     cross-platform core: C++17, CMake, flat C ABI, no UI
./          C++Builder + FireMonkey client, interface only
```

The client sits in the repository root rather than a subdirectory: the C++Builder MSBuild
toolchain resolves `.fmx` form resources relative to the project file, and moving the units
into a folder broke the build.

The core is deliberately kept out of C++Builder: OpenSSL 3.5+, BLAKE3 and zstd build with
MSVC/clang and CMake. The UI loads the resulting DLL through the C ABI.

## Building the core

Requires CMake 3.21+, a C++17 compiler, and [vcpkg](https://github.com/microsoft/vcpkg)
with `VCPKG_ROOT` set. Dependencies are pinned in `bbcore/vcpkg.json`; the first configure
builds OpenSSL from source and takes several minutes. BLAKE3 comes from the same manifest.

```bash
cd bbcore && cmake --preset windows && cmake --build --preset windows && ctest --preset windows
```

Use the `linux` or `macos` preset on those platforms.

So far the build has only been exercised with MSVC on Windows. The POSIX paths are
straightforward but untested; reports of breakage on Linux or macOS are welcome.

## Security notice

This project has not been audited. The hybrid KEM combiner is a custom construction and is
scheduled for independent review before any stable release. Do not rely on BitBackup for
data you cannot afford to lose.

## License

[Apache License 2.0](LICENSE).
