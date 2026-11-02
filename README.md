# Nosy

Fast HTTP/HTTPS intercepting proxy with a web UI — Proxy History and Repeater.
Rust core (tokio · hyper · rustls · SQLite) with a Vue 3 UI embedded, shipped as **one binary**.

This is the core repository of the [nosyproxy](https://github.com/nosyproxy) organization:

| repo | what |
|---|---|
| [`nosy`](https://github.com/nosyproxy/nosy) | proxy engine, storage, Repeater, REST/WebSocket API, the `nosy` binary (this repo) |
| [`nosy-web`](https://github.com/nosyproxy/nosy-web) | Vue 3 web UI, embedded into `nosy` at build time |
| [`nosy-mcp`](https://github.com/nosyproxy/nosy-mcp) | MCP server for AI agents, talks to a running `nosy` |

## Quick start

The repos are expected side by side:

```sh
mkdir nosy && cd nosy
git clone git@github.com:nosyproxy/nosy.git
git clone git@github.com:nosyproxy/nosy-web.git
make -C nosy build                # builds ../nosy-web/dist, then target/release/nosy with the UI embedded
./nosy/target/release/nosy --open # proxy on 127.0.0.1:8080, UI on http://127.0.0.1:1337
```

Trust the CA (`~/.local/share/nosy/ca.crt`, or open `http://nosy/` through the proxy), then:

```sh
curl -x http://127.0.0.1:8080 --cacert ~/.local/share/nosy/ca.crt https://example.com
```

`nosy --help` lists options: `--proxy`, `--ui`, `--project <file.db>`, `--data-dir`,
`--verify-upstream`, `--max-capture-mb`, `--open`.

## Features

- MITM for HTTP/1.1 and HTTP/2 (ALPN on both sides), WebSocket pass-through, per-host certificates
  minted on demand (shared leaf key ⇒ one ECDSA signature per new host, cached).
- Streaming capture: bodies are teed while forwarded — no buffering, no added latency.
- Project = SQLite file; batched writer thread; history survives restarts.
- History: virtualized table (100k+ rows), live updates over WebSocket, filters
  (URL, host glob, method, status class, hide static), sorting, highlights, notes, cURL export.
- Viewer: Raw / Headers / Pretty (JSON, HTML, XML) / Render / Hex; gzip, deflate, br, zstd decoding;
  charset-aware text (e.g. windows-1251).
- Render: HTML in a `sandbox=""` iframe (no scripts, forms or popups) with an injected CSP —
  external resources blocked by default, optionally loaded from the original site; images and SVG
  via `blob:` URLs.
- Repeater: tabs persisted in the project, HTTP/1.x sent **byte-for-byte** (malformed requests stay
  malformed), HTTP/2 via hyper, history per tab, TTFB/total timing, cancel.
- Decoder: chains of Base64 / Base64URL / URL / HTML entities / Hex / `\u` escapes / JWT, gzip & deflate
  (native streams), MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512; “Smart decode” peels nested encodings
  (e.g. URL → Base64 → gzip → JSON). Runs entirely in the browser.
- Selection inspector: select text in any viewer or the Repeater editor to see it decoded inline;
  right-click to send it to the Decoder or transform it in place (`Ctrl+U` / `Ctrl+Shift+U` URL,
  `Ctrl+B` / `Ctrl+Shift+B` Base64).
- UI: English / Russian, dark / light / system theme, accent colors, interface scale, editor font
  size, table density, line numbers, time format… (stored in the browser).
- UI API is protected against DNS rebinding and cross-origin requests from proxied pages; the SPA
  is served with a strict CSP (`script-src 'self'`).

## MCP (AI agents)

The MCP server lives in [`nosy-mcp`](https://github.com/nosyproxy/nosy-mcp): it drives a running
`nosy` through its local API, so the agent's requests land in the **MCP** Repeater tab and its
highlights and notes show up in the history instantly.

## Layout

| crate           | role                                                        |
|-----------------|-------------------------------------------------------------|
| `nosy-model`    | shared API types (exported to TypeScript with ts-rs)        |
| `nosy-ca`       | CA generation, leaf certificates, per-host TLS config cache |
| `nosy-proxy`    | proxy engine (CONNECT, TLS, h1/h2, forwarding, capture)     |
| `nosy-store`    | SQLite schema, batched writer, queries                      |
| `nosy-repeater` | raw request sender                                          |
| `nosy-codec`    | content decompression + Decoder transforms (shared)         |
| `nosy-server`   | `nosy` binary: CLI, REST + WebSocket API, embedded SPA      |

## Contracts with the other repos

- **UI**: `nosy-server` embeds the directory in `NOSY_UI_DIR` with rust-embed (default
  `../nosy-web/dist`, see `.cargo/config.toml`; debug builds read it from disk).
- **Types**: everything crossing the API is in `nosy-model` and derives `ts_rs::TS`. After changing
  it, run `make types` in `nosy-web` and commit the regenerated `src/api/generated` there.
  (`cargo test` here writes the bindings to `target/ts-bindings`.)
- **MCP**: `nosy-mcp` depends on `nosy-model` and `nosy-codec`, and on `nosy-server` for its e2e test.

## Development

```sh
make dev        # backend (debug) — serves ../nosy-web/dist from disk
make check      # fmt, clippy -D warnings, all tests
cargo run --release -p nosy-proxy --example bench   # throughput: direct vs via proxy
```

For the UI with hot reload run `make dev` in `nosy-web` (Vite on :5173, proxies `/api` to :1337).
