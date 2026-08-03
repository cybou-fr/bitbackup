# BitBackup

Cross-platform client for encrypted backup and file transfer.

A file is split into chunks of pseudorandom size. Each chunk is encrypted and becomes a
self-contained object. Reed–Solomon adds redundancy. There are no manifest files, no server
indexes, no required database — **any surviving chunk lets you derive the names of all the
others and reconstruct the whole file.**

The storage stays dumb. It only stores, returns, checks existence, and lists objects. All
cryptography and all logic live in the client.

## Properties

* **Post-quantum first.** Hybrid ML-KEM-1024 + X25519 — an attacker has to break both schemes.
  Protects against "harvest now, decrypt later."
* **Nothing readable on the device.** No keys on disk. The client starts and waits for your
  mnemonic. Each identity's state lives in its own file encrypted to that identity's public
  key; without the mnemonic it is indistinguishable from random bytes. A lost or seized
  device reveals neither your data nor where it is backed up.
* **Only chunks in the storage.** A folder or a bucket holding encrypted objects, nothing
  else — no manifests, no indexes, no marker files.
* **Zero-knowledge storage.** The provider never learns file names, paths, original sizes,
  chunk counts, chunk ordering, which objects are data vs. parity, or which objects belong
  to the same file.
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

Early development. The `bbk/1` container format is designed and frozen; the core is
partially implemented.

| Component | State |
|---|---|
| Format specification | done |
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
| Compression (zstd) | not started |
| Reed–Solomon | not started |
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
