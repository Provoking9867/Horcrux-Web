# Horcrux (Web Edition)

Pure browser implementation of Horcrux — no Python, no server, no installation.
Works fully offline from a local folder or USB drive.

## Files

- **`horcrux.html`** — Main app. Open in any browser.
- **`horcrux-core.js`** — Crypto engine: AES-256-CBC (Web Crypto API), PBKDF2, GF(2^deg) Shamir's Secret Sharing, XTEA diffusion.
- **`diceware.js`** — EFF Large Wordlist lookup for diceware passphrase generation.
- **`eff_wordlist.js`** — Embedded EFF Large Wordlist (7,776 entries).
- **`fflate.js`** — Vendored zip/unzip library (MIT licensed).

## Usage

1. Download all 5 files into the same folder.
2. Open `horcrux.html` in Chrome, Edge, Firefox, or Safari.
3. Everything runs locally in your browser. Nothing is sent to the internet.

### Create Vault
- Enter a Vault ID, select a folder, configure shards/threshold, generate a diceware passphrase, and click Create.
- On Chromium browsers (Chrome/Edge): writes shard folders directly to a directory you choose.
- On other browsers: downloads a zip containing all shard folders.

### Recover Vault
- Enter shard strings and click Combine Shards to verify the passphrase.
- Select the `.enc` file and click Unlock Vault.
- Recovered files are written to disk (Chromium) or downloaded as a zip.

## Offline / USB Drive Use

All dependencies are vendored locally. No internet connection is required.
The entire project can be copied to a USB drive alongside the shard data
so that recovery is possible years later without needing to download anything.

## Compatibility

- Vaults created with this web edition produce **byte-identical** encrypted output to the Python edition (`horcrux.py`), and vice versa.
- Shards are interchangeable between the Python and web editions.

## Dependencies (all vendored locally)

- **fflate** — zip/unzip (MIT licensed, vendored as `fflate.js`)
- **Web Crypto API** — built into all modern browsers
- **EFF Large Wordlist** — embedded in `eff_wordlist.js` (CC-BY 3.0 US)

## Forked from

[Horcrux-Python](../Horcrux-Python/) — the original Python implementation with local HTTP server.
