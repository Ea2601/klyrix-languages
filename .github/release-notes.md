Signed language list (`index.json`) for the Klyrix Gate panel, plus the language packs that changed in this release.
Packs that did not change stay in the release where they first appeared; `index.json` points to them by path.

Devices verify the Ed25519 signature of `index.json` and the sha256 of each pack before installing it.
