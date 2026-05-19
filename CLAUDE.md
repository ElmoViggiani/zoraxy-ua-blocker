# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Zoraxy v3 reverse-proxy plugin (Go binary) that blocks incoming HTTP requests whose `User-Agent` header contains any string from a user-managed blocklist (case-insensitive substring match → HTTP 403). Ships as a single binary with the web UI embedded via `go:embed`.

## Build & run

```sh
go mod tidy
go build -o zoraxy-ua-blocker            # local dev / vet only
env GOOS=linux GOARCH=amd64 \
    go build -o zoraxy-ua-blocker        # deployable artifact (Zoraxy runs on Linux)
```

Development happens on macOS; the deploy target is a Linux Zoraxy host. A plain `go build` on macOS produces a darwin binary that the target cannot execute — always cross-compile when producing the artifact to ship.

There are no tests in the repo. The binary is not run standalone — Zoraxy invokes it with `-introspect` (to read its manifest) and `-configure <json>` (to start it on an assigned port). See `mod/plugins/zoraxy_plugin/zoraxy_plugin.go` for the handshake protocol.

## Architecture

The plugin is a small HTTP server (bound to `127.0.0.1:<port>` assigned by Zoraxy) with three responsibilities wired up in `main.go`:

1. **Dynamic capture pipeline** — Zoraxy POSTs every request to the sniff endpoint (`CAPTURE_SNIFF`). `sniffHandler` extracts the User-Agent, calls `blocklist.RecordMatch`, and returns `Accept` (Zoraxy then re-routes to `CAPTURE_INGRESS` → 403) or `Skip` (pass through). The two-step sniff/ingress dance is required by the Zoraxy SDK in `mod/plugins/zoraxy_plugin/dynamic_router.go`.

2. **Storage (`mod/store/store.go`)** — `BlockList` keeps entries + per-entry match counts in memory under an `RWMutex`, persisted to `uablocker_data.json` next to the binary. List edits (Add/Remove/Reset) save synchronously; match increments only set a `dirty` flag and are batched by a background goroutine (`runFlusher`, default 5s) to avoid disk thrashing under load. On SIGTERM the flusher is stopped and one final `FlushIfDirty` runs before exit — losing this would drop up to `FLUSH_INTERVAL` of counter increments.

3. **Embedded UI + JSON API** — `web/` is embedded into the binary. The UI router from the Zoraxy SDK (`NewPluginEmbedUIRouter`) is wrapped with a `noCache` middleware in `main.go`; this is **load-bearing**, not cosmetic: the SDK injects a per-request CSRF token into the HTML, and without `Cache-Control: no-store` the browser pairs a stale cached token with a fresh session cookie → 403. The JSON API (`/ui/api/{list,add,delete,reset}`) requires `X-CSRF-Token` on POSTs; `script.js` always sends a `URLSearchParams` body (even when empty) because Zoraxy's CSRF middleware rejects body-less POSTs before checking the token.

## Things to know before editing

- **Don't edit `mod/plugins/zoraxy_plugin/`** — it's vendored from upstream Zoraxy (per its `README.txt`, copy/replace rather than modify). Changes there get clobbered on SDK updates.
- **Matching is substring + case-insensitive** — `RecordMatch` uses `strings.Contains` against a cached lowercased copy of the entry value (see invariant below). `Add` dedupes via `strings.EqualFold`. Don't tighten to exact match without checking the README's documented behavior.
- **`Entry.lower` invariant** — `Entry` has an unexported `lower` field caching `strings.ToLower(Value)`, used by the hot-path match. It is populated in two places: `Add` (when a new entry is created) and `NewBlockList` (after JSON unmarshal). Any new code path that constructs an `Entry` directly must set `lower` too, or matching will silently fail for that row. The field is unexported, so `encoding/json` skips it and the on-disk shape is unchanged.
- **Counter accounting on Remove** — `Remove` subtracts the deleted entry's count from `TotalBlocked` so the UI's headline number stays equal to the sum of visible per-entry counts. Preserve this invariant.
