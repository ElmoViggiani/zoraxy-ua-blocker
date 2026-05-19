// Package main is the entry point for the zoraxy-ua-blocker plugin.
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ElmoViggiani/zoraxy-ua-blocker/mod/plugins/zoraxy_plugin"
	"github.com/ElmoViggiani/zoraxy-ua-blocker/mod/store"
)

// Plugin identity constants.
const (
	PLUGIN_ID       = "com.github.ElmoViggiani.zoraxy-ua-blocker"
	PLUGIN_NAME     = "User-Agent Blocker"
	UI_PATH         = "/ui"
	CAPTURE_SNIFF   = "/capture/dynamic/sniff"
	CAPTURE_INGRESS = "/capture/dynamic/ingress"
	STORAGE_FILE    = "uablocker_data.json"

	// How often the background flusher persists in-memory counter
	// increments to disk. Tunable; smaller = fresher data on crash,
	// larger = fewer disk writes.
	FLUSH_INTERVAL = 5 * time.Second
)

// Embed the web UI files into the binary so the plugin ships as one file.
//
//go:embed web
var webFS embed.FS

// Package-level blocklist instance; initialised in main().
var blocklist *store.BlockList

func main() {
	// Strip Go's default timestamp prefix; Zoraxy's plugin manager
	// already stamps every log line we emit.
	log.SetFlags(0)

	// --- 1. Plugin manifest -------------------------------------------
	intro := &zoraxy_plugin.IntroSpect{
		ID:                    PLUGIN_ID,
		Name:                  PLUGIN_NAME,
		Author:                "Elmo Viggiani",
		AuthorContact:         "https://github.com/ElmoViggiani/zoraxy-ua-blocker/issues",
		Description:           "Blocks requests by User-Agent header substring match.",
		URL:                   "https://github.com/ElmoViggiani/zoraxy-ua-blocker",
		Type:                  zoraxy_plugin.PluginType_Router,
		VersionMajor:          1,
		VersionMinor:          1,
		VersionPatch:          0,
		DynamicCaptureSniff:   CAPTURE_SNIFF,
		DynamicCaptureIngress: CAPTURE_INGRESS,
		UIPath:                UI_PATH,
	}

	// --- 2. Handshake with Zoraxy -------------------------------------
	runtimeCfg, err := zoraxy_plugin.ServeAndRecvSpec(intro)
	if err != nil {
		log.Fatalf("failed to handshake with Zoraxy: %v", err)
	}

	// --- 3. Open persistent storage (auto-migrates v1 → v2) ----------
	bl, err := store.NewBlockList(STORAGE_FILE)
	if err != nil {
		log.Fatalf("failed to open blocklist storage: %v", err)
	}
	blocklist = bl

	// --- 4. Background flusher ---------------------------------------
	// Counters increment on every match. Persisting on each one would
	// be disk-thrashy on busy sites, so we hold the increments in
	// memory and flush every FLUSH_INTERVAL only if anything changed.
	stopFlusher := make(chan struct{})
	go runFlusher(blocklist, FLUSH_INTERVAL, stopFlusher)

	// --- 5. Signal handling for clean shutdown -----------------------
	// Zoraxy sends SIGTERM when stopping a plugin. We catch it, stop
	// the flusher, do one final flush, then exit so no counter
	// increments from the last < FLUSH_INTERVAL seconds are lost.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("shutdown: flushing counters")
		close(stopFlusher)
		if err := blocklist.FlushIfDirty(); err != nil {
			log.Printf("final flush error: %v", err)
		}
		os.Exit(0)
	}()

	// --- 6. HTTP routing ---------------------------------------------
	mux := http.NewServeMux()

	// Dynamic capture via the SDK (subtree-pattern aware).
	pathRouter := zoraxy_plugin.NewPathRouter()
	pathRouter.RegisterDynamicSniffHandler(CAPTURE_SNIFF, mux, sniffHandler)
	pathRouter.RegisterDynamicCaptureHandle(CAPTURE_INGRESS, mux, handleIngress)

	// Wrap the SDK UI router so every response carries no-store headers.
	// Without this, http.FileServer's ETag/Last-Modified behaviour combines
	// with the per-request CSRF token injection to serve stale HTML whose
	// embedded token no longer matches the user's session cookie -> 403.
	uiRouter := zoraxy_plugin.NewPluginEmbedUIRouter(PLUGIN_ID, &webFS, "web", UI_PATH)
	uiMux := http.NewServeMux()
	uiRouter.AttachHandlerToMux(uiMux)
	mux.Handle(UI_PATH+"/", noCache(uiMux))

	// JSON API for the UI.
	mux.HandleFunc(UI_PATH+"/api/list", handleAPIList)
	mux.HandleFunc(UI_PATH+"/api/add", handleAPIAdd)
	mux.HandleFunc(UI_PATH+"/api/delete", handleAPIDelete)
	mux.HandleFunc(UI_PATH+"/api/reset", handleAPIReset)

	// --- 7. Run --------------------------------------------------------
	// Explicit http.Server with timeouts so a slow or stuck client can't
	// pin a goroutine indefinitely. Zoraxy talks to us via 127.0.0.1 so
	// requests are fast in practice; the limits exist for misbehaving
	// peers (slowloris-style probes, half-open connections).
	addr := fmt.Sprintf("127.0.0.1:%d", runtimeCfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("%s listening on %s", PLUGIN_NAME, addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("plugin HTTP server died: %v", err)
	}
}

// runFlusher ticks every `interval` and asks the blocklist to persist
// any pending counter increments. Exits when `stop` is closed.
func runFlusher(bl *store.BlockList, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := bl.FlushIfDirty(); err != nil {
				log.Printf("blocklist flush error: %v", err)
			}
		case <-stop:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

// sniffHandler is the SDK SniffHandler callback. Inspect the User-Agent
// and record a match (incrementing counters) if any blocklist entry
// matches; return Accept to forward to ingress (= 403), else Skip.
func sniffHandler(req *zoraxy_plugin.DynamicSniffForwardRequest) zoraxy_plugin.SniffResult {
	ua := firstHeader(req.Header, "User-Agent")
	if ua == "" {
		return zoraxy_plugin.SniffResultSkip
	}
	matched := blocklist.RecordMatch(ua)
	if matched == "" {
		return zoraxy_plugin.SniffResultSkip
	}

	// Include the client IP alongside the User-Agent so the log is useful
	// for spotting individual offenders / abusive sources.
	log.Printf("[origin: %s] [client: %s] [matched: %q] [useragent: %q] %s %s",
		req.Hostname, clientIP(req), matched, ua, req.Method, req.URL)
	return zoraxy_plugin.SniffResultAccept
}

// handleIngress runs only when sniffHandler accepted; we return 403.
func handleIngress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("Forbidden"))
}

// ---------------------------------------------------------------------------
// JSON API
// ---------------------------------------------------------------------------

// handleAPIList returns the current blocklist + total as a JSON snapshot.
func handleAPIList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, blocklist.Snapshot())
}

// handleAPIAdd inserts a new substring into the blocklist.
func handleAPIAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	v := strings.TrimSpace(r.FormValue("value"))
	if v == "" {
		http.Error(w, "value required", http.StatusBadRequest)
		return
	}
	if err := blocklist.Add(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleAPIDelete removes a substring from the blocklist.
func handleAPIDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	v := r.FormValue("value")
	if v == "" {
		http.Error(w, "value required", http.StatusBadRequest)
		return
	}
	if err := blocklist.Remove(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleAPIReset zeros all per-entry counters and the global total.
func handleAPIReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := blocklist.ResetCounts(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// writeJSON emits a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// firstHeader returns the first value of a header by name, tolerating
// case differences in the key.
func firstHeader(h map[string][]string, name string) string {
	if v, ok := h[name]; ok && len(v) > 0 {
		return v[0]
	}
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// clientIP returns the best-effort client IP for logging. Preference:
// X-Forwarded-For (left-most) → X-Real-IP → RemoteAddr (port stripped).
func clientIP(req *zoraxy_plugin.DynamicSniffForwardRequest) string {
	if xff := firstHeader(req.Header, "X-Forwarded-For"); xff != "" {
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	if xr := firstHeader(req.Header, "X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}

// noCache wraps an http.Handler with response headers that ask the
// browser not to cache the body. Required for the plugin UI because the
// HTML contains a per-request CSRF token; serving a cached body would
// pair a stale token with a fresh session cookie and trigger 403.
func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		h.ServeHTTP(w, r)
	})
}
