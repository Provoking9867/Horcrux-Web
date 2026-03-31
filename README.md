# Horcrux (Browser Edition)

Pure browser implementation of Horcrux — no Python, no server, no installation.

## Files

- **`horcrux.html`** — Main app. Open in any browser.
- **`horcrux-core.js`** — Crypto engine: AES-256-CBC (Web Crypto API), PBKDF2, GF(2^deg) Shamir's Secret Sharing, XTEA diffusion.
- **`diceware.js`** — EFF Large Wordlist loader for diceware passphrase generation.

## Usage

1. Open `horcrux.html` in Chrome, Edge, Firefox, or Safari.
2. Everything runs locally in your browser. Nothing is sent to the internet.

### Create Vault
- Enter a Vault ID, select a folder, configure shards/threshold, generate a diceware passphrase, and click Create.
- On Chromium browsers (Chrome/Edge): writes shard folders directly to a directory you choose.
- On other browsers: downloads a zip containing all shard folders.

### Recover Vault
- Enter shard strings and click Combine Shards to verify the passphrase.
- Select the `.enc` file and click Unlock Vault.
- Recovered files are written to disk (Chromium) or downloaded as a zip.

## Compatibility

- Vaults created with this browser edition produce **byte-identical** encrypted output to the Python edition (`horcrux.py`), and vice versa.
- Shards are interchangeable between the Python and browser editions.

## Dependencies

- [fflate](https://github.com/101arrowz/fflate) (loaded from CDN) — zip/unzip. Can be vendored locally for offline use.
- Web Crypto API (built into all modern browsers)
- EFF Large Wordlist (fetched once from eff.org or loaded from a local file, cached in localStorage)

## Forked from

[Horcrux-Python](../Horcrux-Python/) — the original Python implementation with local HTTP server.
