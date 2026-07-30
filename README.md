# Encrypted IBKR portfolio dashboard

Public GitHub Pages frontend for `temp-zero-inode-839-data`.

This repository intentionally contains no plaintext portfolio data, IBKR credentials,
account identifiers, or encryption password. The private pipeline publishes only
`data/portfolio.enc`, encrypted with AES-256-GCM. Password derivation and decryption happen
locally in the browser through Web Crypto.

## Files

- `index.html` — markup and the Content-Security-Policy the page enforces on itself.
- `app.js` — an ES module: decryption, key storage, filters, table and panels.
- `charts.js` — SVG chart primitives imported by `app.js`.
- `styles.css` — design tokens for both themes; every colour used by a chart is a
  custom property, so the two themes swap in one place.

The CSP carries no `unsafe-inline` for styles. A `style="…"` attribute is therefore
dropped by the browser, and anything sized that way renders at zero — chart geometry
lives in SVG attributes, and code that must set a style uses `element.style`.

## Local preview

Serve this directory with any static web server. Opening `index.html` directly may prevent
the browser from fetching the encrypted file because of local-file security rules.

```powershell
python -m http.server 8080
```

Before the first private-pipeline run, the page displays a setup message because
`data/portfolio.enc` does not exist yet.

## GitHub Pages

The included workflow deploys after the browser checks pass. A push to `main` starts
"Frontend checks"; the deployment runs on its completion and only if it succeeded,
against the exact commit that was checked. A push to the `payload` branch — the branch
the private pipeline force-pushes `data/portfolio.enc` to every time it publishes —
deploys immediately, because publication must never wait on a browser, but it takes the
site code from the last commit of `main` the checks passed on rather than from its tip.
Otherwise the next publication would put a rejected commit live half an hour after the
checks rejected it. In repository settings, Pages must use **GitHub Actions** as its
source. The public URL is normally:

`https://<owner>.github.io/temp-zero-inode-839/`

The site is publicly reachable, but its financial payload is not readable without the
dashboard password. Do not weaken this boundary by adding plaintext JSON for debugging.
