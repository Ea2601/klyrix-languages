# Klyrix Gate language packs

Signed translations for the Klyrix Gate panel. The panel is written in Turkish; English ships inside the panel itself.
Every other language is a pack in this repository, and a device downloads a pack only when someone picks that language.

**Language packs are downloaded on request from GitHub.** A device contacts GitHub only when you open the Language page,
during first setup, or for its once-a-day check of a pack that is already installed. The request carries no device
information. GitHub sees your IP address, and the download counts of this repository are public.

Panel support for downloading packs is still being built; until it ships, no device downloads anything from here.

Do not edit this repository by hand. A pipeline in a private translation repository checks every uploaded translation,
builds the packs, signs the list and pushes it here.

## Layout

| Path | What it is |
|---|---|
| `index.json` | The signed list of languages: `{ "kid", "sig", "payload" }` |
| `lp-<n>/<lang>.json.gz` | Packs added in release `lp-<n>` (gzip, UTF-8 JSON) |
| `keys.json` | Public keys that may sign `index.json` |
| `.github/verify.mjs` | Signature and pack checker (Node.js, no dependencies) |

Each release `lp-<n>` carries `index.json` and the packs that changed in it. The same files are in the git tree, so the
list and the packs can also be fetched from `raw.githubusercontent.com` or jsDelivr.

## `index.json`

An envelope with the signature and the signed text side by side:

- `kid`: the signing key, listed in `keys.json`. Role `ci` signs normal releases; role `yedek` is an offline backup key.
- `sig`: Ed25519 signature (base64url) over the UTF-8 bytes of `payload`.
- `payload`: a JSON string with `format`, `seq` (only ever increases), `content` (the release whose packs this list
  points to; differs from `seq` after a rollback), `published`, `mirrors` (base URLs), `revoked`, `langs` and
  `embedded`.
- `langs[]`: `code`, `name` (in its own language), `dir`, `script`, `ver`, `minBuild`, `path`, `bytes`, `rawBytes`,
  `sha256`, `keys` and `coverage` (percent of texts translated, per area).
- `embedded[]`: same fields. English is listed here: the panel ships it, and devices do not install it as a pack.
- `revoked`: `null`, or a revocation list signed by the offline backup key. A device that sees it never accepts the
  listed keys again.

A pack is `{ "<key>": { "t": "<text>", "src": "<first 8 hex of sha256 of the Turkish source>", "h": [[src, text], ...] } }`.
`h` keeps up to three older translations for panels that still show the older Turkish text.

## Verify

```
node .github/verify.mjs index.json keys.json --paketler .
```

The release workflow runs the same check before it publishes anything.
