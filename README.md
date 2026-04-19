# Horcrux (Web Edition)

Self-hosted digital-estate-planning tool: encrypt a folder of files, split the key among N trusted people, recover with any K of them. Pure browser — no Python, no server, no installation. Works fully offline from a local folder or USB drive.

## What it does

1. Encrypt a folder of files with a random diceware passphrase.
2. Split that passphrase into N "shards" via Shamir's Secret Sharing.
3. Each holder gets one shard on a USB drive (along with a copy of the tool itself).
4. Any K of the N holders, together, can recover the files.

Fewer than K shards reveals nothing about the secret.

## Files

- `horcrux.html` — the tool. Open in any modern browser.
- `horcrux-core.js` — crypto engine: AES-256-CBC + HMAC-SHA256, PBKDF2-HMAC-SHA256 at 600k iterations, GF(2^deg) Shamir's Secret Sharing, XTEA diffusion.
- `diceware.js` — EFF Large Wordlist passphrase generator.
- `eff_wordlist.js` — embedded 7,776-entry EFF wordlist.
- `fflate.js` — vendored zip/unzip library (MIT).

All five files together (~225 KB) are what needs to live on each shard USB for self-contained long-term recovery.

## Vault format (Horcrux1)

```
[ 8B "Horcrux1" ] [ 16B salt ] [ ciphertext ] [ 32B HMAC-SHA256 tag ]
```

- PBKDF2-HMAC-SHA256, **600,000 iterations**, 80 bytes out → 32B AES-256 key + 16B CBC IV + 32B HMAC key.
- Encrypt-then-MAC: HMAC covers `magic ‖ salt ‖ ciphertext`, verified in constant time before any AES decryption.
- Inside the encrypted zip, a `Vault_Manifest.txt` records SHA-256 of every file. On recovery the manifest is verified; tampering causes a generic integrity-failure message and nothing is written to disk.

### Legacy format (read-only)

Vaults in OpenSSL `Salted__` format (from the Python `horcrux.py` v1.2, or from pre-Phase-2 Web builds) remain readable with a UI warning. PBKDF2 100,000 iterations, 48-byte derivation, no HMAC. Writing the legacy format is no longer supported; recover a legacy vault and create a new one to upgrade.

## Usage

### Create

1. Open `horcrux.html` in Chrome, Edge, Firefox, or Safari (double-click works; `file://` is fine).
2. **Create Vault** tab. Enter a Vault ID (2–20 characters — e.g. `MOM-2026`).
3. Pick the folder to encrypt, set total shards (N) and threshold (K).
4. Roll physical dice to build a 5-word diceware passphrase.
5. Click Create Encrypted Vault.
   - **Chromium (Chrome/Edge):** pick a folder; the tool writes N `Shard_N/` directories into it.
   - **Firefox/Safari, or if you cancel:** the results page shows a Download button per shard. Each produces a flat zip (`Vault_XX_Shard_N.zip`).
6. Copy the five tool files **plus** the shard folder/zip onto each USB drive.
7. Delete every local copy of the shard files after distribution.

### Recover

1. Open `horcrux.html` from any of the USBs.
2. **Recover Vault** tab. Set threshold K, paste each shard `.txt` content into the boxes.
3. Click Combine Shards — the 5-word passphrase appears. Extras tolerate a typo: supply more than K shards and the tool tries every K-subset until one works.
4. Pick `Vault_XX.enc`, click Unlock Vault.

## Security properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-CBC with PBKDF2-stretched diceware passphrase |
| Container integrity | HMAC-SHA256 (Horcrux1 only; legacy format has none) |
| File integrity | SHA-256 per file in `Vault_Manifest.txt`, verified on recovery |
| Availability | Shamir K-of-N threshold; <K shards reveals nothing |
| Offline | All dependencies vendored; zero network calls at runtime |

## Compatibility

- Shard strings (Shamir split/combine) remain interchangeable with the Python edition.
- **Vault ciphertext is no longer interchangeable** with `horcrux.py` v1.2 — it cannot decrypt Horcrux1. The Python side needs to be updated to match if interop matters.
- Not compatible with B. Poettering's `ssss-split` / `ssss-combine` tools (different polynomial structure and byte order).

## Dependencies (all vendored locally)

- **Web Crypto API** — built into all modern browsers
- **fflate** — DEFLATE zip, MIT licensed
- **EFF Large Wordlist** — CC-BY 3.0 US

## Origin and recent history

Forked from a Python edition with a local HTTP server. Rewritten for the browser, then substantially hardened in two phases:

- **Phase 1:** manifest verification on recovery, XSS hardening, cancel-safety on directory picker, subset retry for mistyped shards, button re-enable on success, redacted filenames from error messages, zip-generation cleanup.
- **Phase 2:** authenticated Horcrux1 vault format (HMAC-SHA256 + PBKDF2 600k), legacy read-compat with UI warning, per-shard Download buttons (replacing the old bulk-download flow), diceware sanity check on Combine Shards, expanded 2–20 character vault IDs.

See commit history for details.
