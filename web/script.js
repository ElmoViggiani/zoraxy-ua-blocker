// API URLs are relative so they work both when the plugin is reached
// directly and when proxied through Zoraxy's /plugin.ui/<id>/ path.
const API_LIST   = "api/list";
const API_ADD    = "api/add";
const API_DELETE = "api/delete";
const API_RESET  = "api/reset";

// Render counts with thousands separators (e.g. "1,243") for readability.
const NUMFMT = new Intl.NumberFormat();

// Read the CSRF token Zoraxy injects into the meta tag at page load.
function csrfToken() {
  const m = document.querySelector('meta[name="zoraxy.csrf.Token"]');
  return m ? m.getAttribute("content") || "" : "";
}

// Wrapper around fetch that adds the CSRF header on every POST.
//
// Important: we *always* send a URLSearchParams body, even when there
// are no params. A POST without a body has no Content-Type, and Zoraxy's
// CSRF middleware rejects such requests before checking X-CSRF-Token —
// which is why /api/reset (a body-less call) used to 403 while /api/add
// and /api/delete (form-bodied) passed.
async function apiPost(url, params) {
  return fetch(url, {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken() },
    body: new URLSearchParams(params || {}),
  });
}
// ---------------------------------------------------------------------------
// Theme synchronisation with Zoraxy
// ---------------------------------------------------------------------------

function applyDark(isDark) {
  document.documentElement.classList.toggle("dark", !!isDark);
}

// Zoraxy invokes this on our window from its themeColorButton handler.
window.setDarkTheme = function (isDark) { applyDark(isDark); };

// One-shot best-effort detection of Zoraxy's initial theme for first paint.
function detectInitialDark() {
  try {
    const pDoc = window.parent.document;
    const body = pDoc.body;
    const html = pDoc.documentElement;
    const darkClasses = ["darkMode", "dark-mode", "dark", "inverted"];
    for (const c of darkClasses) {
      if (body.classList.contains(c) || html.classList.contains(c)) return true;
    }
    if (body.getAttribute("data-theme") === "dark") return true;
    if (html.getAttribute("data-theme") === "dark") return true;
    try {
      const ls = window.parent.localStorage;
      const stored = ls.getItem("theme") || ls.getItem("darkMode");
      if (stored === "dark" || stored === "true" || stored === "1") return true;
    } catch (_) { /* localStorage may be locked down; ignore */ }
    const bg = window.parent.getComputedStyle(body).backgroundColor;
    const m = bg && bg.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
    if (m) {
      const luminance = (0.299 * +m[1] + 0.587 * +m[2] + 0.114 * +m[3]) / 255;
      return luminance < 0.5;
    }
    return false;
  } catch (_) {
    return false;
  }
}
applyDark(detectInitialDark());

// ---------------------------------------------------------------------------
// Data rendering
// ---------------------------------------------------------------------------

async function refresh() {
  let snap;
  try {
    const res = await fetch(API_LIST);
    snap = await res.json();
  } catch (e) {
    return;
  }

  document.getElementById("totalCount").textContent =
    NUMFMT.format(snap.total_blocked || 0);

  const ul = document.getElementById("list");
  ul.innerHTML = "";
  for (const e of snap.entries || []) {
    const li = document.createElement("li");

    const valueSpan = document.createElement("span");
    valueSpan.className = "value";
    valueSpan.textContent = e.value;

    const countSpan = document.createElement("span");
    countSpan.className = "count";
    countSpan.textContent = `blocked ${NUMFMT.format(e.count)} times`;

    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Delete";
    btn.onclick = () => remove(e.value);

    li.appendChild(valueSpan);
    li.appendChild(countSpan);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

async function add(value)    { await apiPost(API_ADD,    { value }); await refresh(); }
async function remove(value) { await apiPost(API_DELETE, { value }); await refresh(); }

// ---------------------------------------------------------------------------
// Reset (two-step "armed" pattern)
// ---------------------------------------------------------------------------
//
// Zoraxy's plugin iframe sandbox does not include the 'allow-modals'
// keyword, so window.confirm() is silently blocked. To still give the
// user a chance to back out of a destructive action, we use a two-step
// arming pattern: the first click swaps the button label to a clear
// "click again to confirm" message and tints it red via the .armed CSS
// class; the second click within RESET_ARM_WINDOW_MS performs the
// reset. After the window expires the button reverts.

let resetArmed = false;
let resetDisarmTimer = null;
const RESET_ARM_WINDOW_MS = 3000;
const RESET_BTN_DEFAULT_LABEL = "Reset all counts";
const RESET_BTN_ARMED_LABEL   = "Click again to confirm";

// disarmReset returns the button to its idle state and clears the timer.
function disarmReset() {
  resetArmed = false;
  if (resetDisarmTimer !== null) {
    clearTimeout(resetDisarmTimer);
    resetDisarmTimer = null;
  }
  const btn = document.getElementById("resetBtn");
  btn.textContent = RESET_BTN_DEFAULT_LABEL;
  btn.classList.remove("armed");
}

async function resetAll() {
  const btn = document.getElementById("resetBtn");

  // First click: arm and start the auto-disarm countdown.
  if (!resetArmed) {
    resetArmed = true;
    btn.textContent = RESET_BTN_ARMED_LABEL;
    btn.classList.add("armed");
    resetDisarmTimer = setTimeout(disarmReset, RESET_ARM_WINDOW_MS);
    return;
  }

  // Second click within the window: actually reset.
  disarmReset();
  await apiPost(API_RESET, null);
  await refresh();
}

// ---------------------------------------------------------------------------
// Submit + wiring
// ---------------------------------------------------------------------------

function onSubmit() {
  const input = document.getElementById("value");
  const v = input.value.trim();
  if (!v) return;
  input.value = "";
  add(v);
}

document.getElementById("submitBtn").addEventListener("click", onSubmit);
document.getElementById("resetBtn").addEventListener("click", resetAll);
document.getElementById("value").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); onSubmit(); }
});

// Initial render, then auto-refresh every 5 s to keep counts live.
refresh();
setInterval(refresh, 5000);
