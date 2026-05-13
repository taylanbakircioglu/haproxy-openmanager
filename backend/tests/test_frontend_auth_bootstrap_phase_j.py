"""Phase J pin tests — frontend auth bootstrap + cluster fetch ordering.

These are static-source assertions on the frontend bundle source. They are
the only safety net we have in CI for a class of bug that only manifests
at mount-time in the React commit phase, which is hard to exercise from a
backend pytest run without a JSDOM harness.

Background — the bug these tests guard against:

The provider hierarchy is
    <AuthProvider>
      <ClusterProvider>
        ... rest of the app ...
      </ClusterProvider>
    </AuthProvider>

React's useEffect commit phase fires CHILD effects before PARENT effects.
That means `ClusterProvider.useEffect` (which fires the very first
`axios.get('/api/clusters')`) runs BEFORE `AuthProvider.useEffect`. The
legacy code path set `axios.defaults.headers.common['Authorization']`
inside the parent's effect — too late. The first cluster request went
out un-authenticated → backend returned 401 → ClusterContext silently
committed `clusters=[]` → operators saw "no clusters" until the 30s
auto-refresh interval re-fired the request, by which point auth had
hydrated. Operators experienced this as

    "I deploy, refresh the page, and clusters don't appear until I
     wait a long time. I close the browser and re-open and clusters
     STILL don't appear for a while. There seems to be a UI problem."

Three layers of defence are now in place; each layer has a pin below:

    1) Module-level axios bootstrap in src/index.js — runs before <App />
       renders, seeds axios.defaults.Authorization synchronously AND
       installs a request interceptor that re-reads the token on every
       outbound request (cannot be raced).

    2) AuthContext synchronous useState lazy initialisers — hydrate
       user / token / axios.defaults during the AuthProvider RENDER
       phase, which precedes ANY child useEffect.

    3) ClusterContext auth-gate + exponential-backoff retry — wait until
       AuthContext has hydrated before the first fetch, and recover from
       transient 5xx / network errors with 4 fast retries instead of
       blanking the cluster list and depending on the 30s interval.
"""

from pathlib import Path

import re

import pytest

_REPO = Path(__file__).resolve().parent.parent.parent
_FRONTEND_SRC = _REPO / "frontend" / "src"
_INDEX = _FRONTEND_SRC / "index.js"
_AUTH = _FRONTEND_SRC / "contexts" / "AuthContext.js"
_CLUSTER = _FRONTEND_SRC / "contexts" / "ClusterContext.js"


def _read_or_skip(path: Path) -> str:
    """Read a frontend source file, or skip the calling test cleanly when
    the frontend tree is not mounted in the current pytest environment.

    The CI Docker test image (``backend/Dockerfile.test``) intentionally
    only mounts ``backend/`` so the unit-test step has a small,
    fast-to-build container. Static-source pins that reference frontend
    files therefore have no source to read in CI Docker — without this
    helper they would blow up with a generic ``FileNotFoundError`` and
    abort the build, even though the pins themselves are correctly
    written. Skipping is the right behaviour: the pins still run on
    every developer's local pytest pass (where the full repo is on
    disk) AND on the corporate-pipeline build step that runs pytest
    from the repository root, which is where regressions would be
    caught."""
    if not path.exists():
        pytest.skip(
            f"frontend tree not mounted at {path} — skipping pin "
            "(runs only when the repo root is available, e.g. local "
            "developer pytest or pipeline integration step)"
        )
    return path.read_text()


# ---------------------------------------------------------------------------
# Layer 1 — module-level axios bootstrap in src/index.js
# ---------------------------------------------------------------------------


def test_phase_j_index_imports_axios_for_bootstrap():
    src = _read_or_skip(_INDEX)
    assert "import axios from 'axios'" in src, (
        "Phase J regression: src/index.js no longer imports axios. The "
        "module-level bootstrap that seeds axios.defaults.Authorization "
        "synchronously (so child useEffects don't race AuthProvider) "
        "depends on this import."
    )


def test_phase_j_index_seeds_default_authorization_header_at_module_load():
    src = _read_or_skip(_INDEX)
    # The bootstrap IIFE must call into both branches: synchronous
    # default-header seed AND a request interceptor.
    assert "axios.defaults.headers.common['Authorization']" in src, (
        "Phase J regression: src/index.js no longer seeds the axios "
        "default Authorization header at module-load time. Without "
        "this, a child provider's mount-time fetch can race the parent "
        "provider's effect and dispatch with no auth header → 401 → "
        "operator sees an empty cluster list."
    )
    assert "axios.interceptors.request.use" in src, (
        "Phase J regression: src/index.js no longer installs a request "
        "interceptor. The interceptor is the belt-and-suspenders defence "
        "that re-reads the token on every outbound request and cannot "
        "be raced by mount ordering."
    )
    # The bootstrap must read from BOTH legacy storage keys for
    # backward compatibility with sessions saved by older builds.
    assert "'token'" in src and "'authToken'" in src, (
        "Phase J regression: src/index.js bootstrap no longer reads "
        "from BOTH the canonical 'token' key and the legacy 'authToken' "
        "key — sessions saved by older builds would silently fail to "
        "authenticate after the upgrade."
    )


def test_phase_j_index_bootstrap_runs_before_react_render():
    """Order matters: the bootstrap IIFE must execute BEFORE
    ReactDOM.createRoot(...).render(...) so that no React tree (and
    therefore no useEffect) can fire before the axios defaults are
    seeded."""
    src = _read_or_skip(_INDEX)
    # Match the IIFE invocation line: "})();" at end of bootstrapAxiosAuth.
    iife_idx = src.find("bootstrapAxiosAuth")
    render_idx = src.find("root.render(")
    assert iife_idx != -1, (
        "Phase J regression: bootstrapAxiosAuth IIFE missing from "
        "src/index.js."
    )
    assert render_idx != -1, (
        "Phase J regression: root.render(<App />) missing from "
        "src/index.js."
    )
    assert iife_idx < render_idx, (
        "Phase J regression: bootstrapAxiosAuth IIFE is declared AFTER "
        "root.render(). The IIFE must run before React renders so the "
        "axios defaults are seeded before ANY useEffect can fire."
    )


# ---------------------------------------------------------------------------
# Layer 2 — AuthContext synchronous useState initialisers
# ---------------------------------------------------------------------------


def test_phase_j_authcontext_uses_lazy_initialisers_to_hydrate_synchronously():
    src = _read_or_skip(_AUTH)
    # The new helper that hydrates from localStorage during the render
    # phase. Pinned by name so a future refactor that drops the helper
    # but keeps the symptom (post-mount async hydration) fails this
    # test.
    assert "_hydrateAuthSync" in src, (
        "Phase J regression: AuthContext no longer defines the "
        "_hydrateAuthSync helper that hydrates auth state during the "
        "render phase. Hydrating in a useEffect re-introduces the "
        "mount-time race that produced the 'wait a while for clusters' "
        "symptom."
    )
    # The lazy initialiser pattern is `useState(_hydrateAuthSync)` for
    # the first state — capturing the result once and feeding the rest.
    assert "useState(_hydrateAuthSync)" in src, (
        "Phase J regression: AuthContext no longer uses the lazy "
        "initialiser form `useState(_hydrateAuthSync)`. Without the "
        "lazy form, the helper would be invoked on every render, "
        "polluting render with side effects and breaking the "
        "single-source-of-truth invariant."
    )
    # axios.defaults.Authorization must be set INSIDE _hydrateAuthSync —
    # verify by locating the helper body and asserting the assignment is
    # within it.
    helper_idx = src.find("const _hydrateAuthSync")
    assert helper_idx != -1
    # The helper body extends until the next top-level `};` close. Match
    # the first `};` that is preceded by a `return {` (the helper's
    # final return) — this is a coarse but stable boundary.
    helper_end = src.find("\n};", helper_idx)
    assert helper_end != -1
    helper_body = src[helper_idx:helper_end]
    assert (
        "axios.defaults.headers.common['Authorization']" in helper_body
    ), (
        "Phase J regression: _hydrateAuthSync no longer seeds the "
        "axios default Authorization header. The provider-level seed "
        "is the belt to the index.js bootstrap's suspenders — without "
        "it, AuthContext is no longer self-sufficient when imported "
        "in isolation (tests / storybook / SSR shims)."
    )


def test_phase_j_authcontext_initial_loading_is_false_by_default():
    """Loading state must default to FALSE post-hydration so child
    consumers (e.g. ClusterContext's auth-gate) can decide immediately
    whether to fetch."""
    src = _read_or_skip(_AUTH)
    # The loading state's initial value comes from the hydration helper,
    # which sets `loading: false` in every code path it returns.
    helper_idx = src.find("const _hydrateAuthSync")
    helper_end = src.find("\n};", helper_idx)
    assert helper_idx != -1 and helper_end != -1
    helper_body = src[helper_idx:helper_end]
    # Every return statement inside the helper must include
    # `loading: false`. Match each `return { … };` block by anchoring on
    # the closing `};` line — a non-greedy `[\s\S]*?` lets the body
    # contain inner braces (e.g. `: {}` defaults).
    return_clauses = re.findall(
        r"return\s*\{[\s\S]*?\n\s*\};", helper_body
    )
    assert return_clauses, (
        "Phase J regression: _hydrateAuthSync no longer contains "
        "return statements — the helper has been gutted."
    )
    for clause in return_clauses:
        assert "loading: false" in clause, (
            "Phase J regression: at least one _hydrateAuthSync return "
            f"branch no longer sets `loading: false`. Branch was:\n{clause}"
        )


# ---------------------------------------------------------------------------
# Layer 3 — ClusterContext auth-gate + exponential-backoff retry
# ---------------------------------------------------------------------------


def test_phase_j_clustercontext_consumes_useauth_for_auth_gate():
    src = _read_or_skip(_CLUSTER)
    assert "import { useAuth } from './AuthContext'" in src, (
        "Phase J regression: ClusterContext no longer imports useAuth. "
        "Without consuming AuthContext, the cluster fetch cannot wait "
        "for auth hydration and re-introduces the mount-time race."
    )
    assert "const { isAuthenticated, loading: authLoading } = useAuth();" in src, (
        "Phase J regression: ClusterContext no longer reads "
        "isAuthenticated / authLoading from AuthContext. The auth-gate "
        "guard depends on these values."
    )


def test_phase_j_clustercontext_skips_fetch_until_auth_is_ready():
    """The fetch effect must short-circuit when auth is still loading
    OR the user isn't authenticated. Both paths matter:
      - authLoading=true: avoid the legacy mount-time race.
      - isAuthenticated=false: avoid a wasted 401 round-trip on the
        public login page and stale data after a session swap.
    """
    src = _read_or_skip(_CLUSTER)
    # The effect body must short-circuit on both conditions before
    # calling fetchClusters.
    assert "if (authLoading) return undefined;" in src, (
        "Phase J regression: ClusterContext no longer short-circuits "
        "when authLoading is true."
    )
    assert "if (!isAuthenticated) {" in src, (
        "Phase J regression: ClusterContext no longer short-circuits "
        "when isAuthenticated is false."
    )
    # The dependency array must include isAuthenticated + authLoading so
    # the effect re-runs (and finally fetches) when the user logs in.
    assert "[isAuthenticated, authLoading, fetchClusters]" in src, (
        "Phase J regression: ClusterContext effect dependency array no "
        "longer includes isAuthenticated/authLoading — the fetch will "
        "not re-run when the user finishes logging in."
    )


def test_phase_j_clustercontext_sets_loading_true_before_first_authgated_fetch():
    """Phase J audit fix #3.

    The auth-gated effect originally took both branches of the gate as
    "settled, loading=false":
        if (!isAuthenticated) {
            ...
            setLoading(false);   ← visible to the UI
            return;
        }
        retryAttemptRef.current = 0;
        fetchClusters();         ← async; flips loading=false at the
                                   end of `finally`, but until then
                                   the UI sees `loading=false` from
                                   the previous branch.

    On the login flow, this produced a 1-2 second window where the UI
    rendered `loading=false + clusters=[]` while /api/clusters was in
    flight. Downstream consumers (Frontends, Backend Servers, SSL
    Certificate Management, etc.) interpreted that as "list loaded,
    zero clusters" and showed the "No Cluster Selected" affordance
    instead of a spinner.

    Pin the explicit `setLoading(true)` immediately before the first
    `fetchClusters()` so consumers see "loading" until the first
    response settles. The 30s background refresh ticks intentionally
    do NOT flip loading (the interval handler calls fetchClusters()
    directly without touching loading), avoiding a periodic spinner
    flicker.
    """
    src = _read_or_skip(_CLUSTER)
    # The first-fetch site of the auth-gated effect must include an
    # explicit setLoading(true) immediately above fetchClusters().
    # We pattern-match the precise sequence with non-greedy \s+ so the
    # pin survives whitespace tweaks but still anchors on the
    # "setLoading(true) → fetchClusters()" pairing.
    assert re.search(
        r"setLoading\(true\)\s*;\s*\n\s*fetchClusters\(\)\s*;",
        src,
    ), (
        "Phase J audit fix #3 regression: ClusterContext no longer "
        "calls setLoading(true) immediately before the first "
        "fetchClusters() inside the auth-gated effect. The login flow "
        "would briefly render `loading=false + clusters=[]` and "
        "downstream consumers would show 'No Cluster Selected' "
        "instead of a spinner for the duration of the round-trip."
    )


def test_phase_j_clustercontext_resets_retry_counter_after_settling():
    """Phase J audit fix #5.

    `retryAttemptRef` was reset only on:
      a) successful fetch (`retryAttemptRef.current = 0` in the success
         branch), and
      b) the auth gate transition (mount / login / logout) at the top
         of the useEffect.

    The "settle into empty state" branch — taken when the retry budget
    is exhausted (4 transient failures in a row) OR when the failure
    was non-retryable (401/403) — did NOT reset the counter. After an
    exhausted run, `retryAttemptRef` stayed at 4 for the entire user
    session, so the very next fetchClusters() invocation:

        - the 30s background refresh interval, which keeps firing
          forever;
        - an explicit fetchClusters() call from one of the mutators
          (addCluster, updateCluster, deleteCluster, testConnection,
          setDefaultCluster);

    …would short-circuit the retry pattern on the FIRST transient
    failure (`retryAttemptRef.current < 4` is false) and dump the
    operator straight back into the empty state. The retry budget
    was effectively a one-shot resource.

    Pin the reset: the empty-state branch must explicitly reset
    `retryAttemptRef.current = 0` so the next invocation gets a fresh
    retry budget.
    """
    src = _read_or_skip(_CLUSTER)
    # Anchor on the unique catch-block "Non-retryable (auth)" comment
    # that lives inside the settle-into-empty-state branch. The
    # success-path empty-state branch (cluster list returned zero
    # clusters from the server) does NOT need this reset because
    # retryAttemptRef is already reset to 0 at the start of the
    # success path.
    anchor_idx = src.find("// Non-retryable (auth) or retries exhausted")
    assert anchor_idx != -1, (
        "Phase J audit fix #5 regression: the catch-block empty-state "
        "branch comment was removed. The pin relies on this comment "
        "as a stable anchor — please update the pin if the comment "
        "moved."
    )
    # Take the next ~1500 chars after the anchor and assert the reset
    # appears within that window (i.e. inside the same branch body).
    # The window has to be generous because the inline rationale
    # comment for the reset is long.
    window = src[anchor_idx: anchor_idx + 1500]
    assert "retryAttemptRef.current = 0" in window, (
        "Phase J audit fix #5 regression: the settle-into-empty-state "
        "branch in fetchClusters no longer resets retryAttemptRef. "
        "An exhausted retry chain would leave the counter at 4 and "
        "every subsequent fetchClusters() invocation would skip the "
        "retry pattern on the first transient failure — silently "
        "downgrading the retry budget to a one-shot resource."
    )


def test_phase_j_clustercontext_keeps_loading_true_while_retry_is_queued():
    """Phase J audit fix #4.

    The first cut of Phase J flipped `loading=false` in `finally` on
    every fetchClusters() invocation, including the ones that scheduled
    a retry. That meant a transient first-fetch failure produced this
    timeline:
        t=0     setLoading(true), clusters=[]
        t=0+    fetchClusters() in flight
        t=Δ     response fails → catch schedules a retry timer →
                finally setLoading(false)
        t=Δ     UI sees `loading=false + clusters=[]` → renders
                "No Cluster Selected" between retry waves
        t=Δ+1s  retry succeeds → clusters populated → re-render

    Up to ~15 seconds of misleading "No Cluster Selected" was visible
    to the operator across the 4-attempt retry budget — exactly the
    symptom Phase J was supposed to eliminate.

    Pin the conditional release: `setLoading(false)` only fires when
    `retryTimerRef.current === null` (i.e. no retry is queued). The
    spinner therefore stays visible across the entire retry budget so
    the operator never sees the empty state until the retries are
    fully exhausted.
    """
    src = _read_or_skip(_CLUSTER)
    # Match the conditional release pattern. Use a flexible whitespace
    # match so the pin survives formatter tweaks.
    assert re.search(
        r"if\s*\(\s*retryTimerRef\.current\s*===\s*null\s*\)\s*\{\s*\n\s*setLoading\(false\)\s*;\s*\n\s*\}",
        src,
    ), (
        "Phase J audit fix #4 regression: ClusterContext finally clause "
        "no longer guards `setLoading(false)` behind "
        "`retryTimerRef.current === null`. Without the guard, the "
        "spinner blinks off between retry waves and the UI flashes "
        '"No Cluster Selected" for up to ~15s while retries are still '
        "in flight."
    )


def test_phase_j_clustercontext_uses_selected_cluster_ref_to_avoid_stale_closure():
    """Phase J audit fix #2.

    `fetchClusters` is wrapped in `useCallback(…, [])` so the 30s
    auto-refresh interval gets a stable reference. That stability comes
    at a cost: any closure-captured state inside the callback freezes
    at the value it had on the first render. The "update existing
    selection with fresh agent data" branch reads `selectedCluster?.id`,
    so without a ref it would read `null` forever — the UI's
    operator-visible agent-health dot would never refresh, defeating
    the whole point of the 30-second interval.

    Pin the well-known fix pattern: keep `selectedCluster` in a ref,
    update the ref via a passive effect, and read the ref inside the
    callback.
    """
    src = _read_or_skip(_CLUSTER)
    assert "selectedClusterRef" in src, (
        "Phase J audit fix #2 regression: ClusterContext no longer "
        "keeps a `selectedClusterRef` ref to bridge the live "
        "`selectedCluster` state into the stable `useCallback` "
        "fetchClusters body. Without it, the 30s auto-refresh updates "
        "stale data — the agent-health dot in the cluster selector "
        "would never refresh."
    )
    # The ref must be updated by a passive effect that depends on
    # `selectedCluster` so each new selection is reflected before the
    # next refresh tick fires.
    assert "selectedClusterRef.current = selectedCluster" in src, (
        "Phase J audit fix #2 regression: ClusterContext no longer "
        "updates `selectedClusterRef.current` from `selectedCluster` "
        "in a passive effect — the ref would never advance past its "
        "initial null value."
    )
    # The callback must READ the ref (not the captured state) so the
    # stale closure cannot reintroduce itself.
    assert "selectedClusterRef.current?.id" in src, (
        "Phase J audit fix #2 regression: ClusterContext no longer "
        "reads the selected cluster id from the ref inside "
        "fetchClusters. Reading the captured `selectedCluster` from "
        "the closure would freeze the value at the first render's "
        "null and break the agent-health refresh."
    )


def test_phase_j_clustercontext_retries_with_exponential_backoff_on_transient_errors():
    src = _read_or_skip(_CLUSTER)
    # The catch block now distinguishes between auth errors (no retry)
    # and transient errors (retry up to 4 times with backoff).
    assert "retryAttemptRef" in src, (
        "Phase J regression: ClusterContext no longer keeps a retry "
        "attempt counter. Without it, a transient 5xx on the first "
        "fetch silently commits an empty cluster list and the user "
        "must wait for the 30s auto-refresh — exactly the symptom "
        "Phase J fixes."
    )
    assert "retryTimerRef" in src, (
        "Phase J regression: ClusterContext no longer keeps a retry "
        "timer ref. The timer must be cleared on unmount and on the "
        "next successful fetch."
    )
    # Cap at 4 attempts and exponential backoff (1s, 2s, 4s, 8s).
    assert "retryAttemptRef.current < 4" in src, (
        "Phase J regression: ClusterContext retry cap moved away from "
        "4 attempts. Total retry budget should be ~15s before settling "
        "into the empty state."
    )
    assert "Math.pow(2, attempt)" in src, (
        "Phase J regression: ClusterContext no longer uses exponential "
        "backoff for retries — switched to fixed delay or removed."
    )
    # 401/403 must NOT trigger a retry — re-auth is the user's job.
    assert "status >= 500" in src, (
        "Phase J regression: ClusterContext no longer restricts retries "
        "to 5xx responses (and network errors). A 401 retry loop would "
        "spam the backend before the user can log in."
    )


# ---------------------------------------------------------------------------
# Phase J audit fix #6 — page-level "loading vs no cluster selected" pins
# ---------------------------------------------------------------------------
#
# The original symptom the user reported was specifically about page
# CONTENT, not about the cluster selector itself. ClusterSelector
# already shows a "Loading clusters..." spinner while the
# ClusterContext is in flight, but the page-level components (SSL
# Management, Configuration, Dashboard, Bulk Config Import, Bulk
# Version History) checked `!selectedCluster` directly and rendered
# their permanent "No Cluster Selected" affordances. During the
# legitimate post-deploy fetch window — including the 15-second
# exponential-backoff retry budget that audit fix #4 deliberately
# keeps `loading=true` for — `selectedCluster` is null but
# `loading=true`, so those pages displayed the misleading "you forgot
# to pick a cluster" message even though the cluster list was simply
# still being fetched.
#
# Audit fix #6 distinguishes the two states at every page-level call
# site by also consuming `loading` from useCluster() and showing a
# neutral "Loading clusters…" affordance during the fetch. Each pin
# below guards one call site so a future regression can't silently
# bring back the user-visible bug.

_PAGES_WITH_NO_CLUSTER_AFFORDANCE = [
    ("frontend/src/components/SSLManagement.js",
     "loading: clustersLoading"),
    ("frontend/src/components/Configuration.js",
     "loading: clustersLoading"),
    ("frontend/src/components/DashboardV2.js",
     "loading: clustersLoading"),
    ("frontend/src/components/BulkConfigImport.js",
     "loading: clustersLoading"),
    ("frontend/src/components/BulkVersionHistory.js",
     "loading: clustersLoading"),
    ("frontend/src/components/BackendServers.js",
     "loading: clustersLoading"),
    ("frontend/src/components/FrontendManagement.js",
     "loading: clustersLoading"),
    ("frontend/src/components/ApplyManagement.js",
     "loading: clustersLoading"),
]


@pytest.mark.parametrize("relpath,marker", _PAGES_WITH_NO_CLUSTER_AFFORDANCE)
def test_phase_j_page_consumes_cluster_loading_state(relpath, marker):
    """Phase J audit fix #6.

    Each page that renders a "No Cluster Selected" affordance must now
    also pull `loading` out of useCluster() so it can distinguish "the
    operator forgot to pick a cluster" from "the cluster list is
    still being fetched". Without this, the retry-budget window keeps
    the page-level warning on screen for up to ~15s after a deploy or
    login — exactly the symptom Phase J was supposed to eliminate.
    """
    path = _REPO / relpath
    src = _read_or_skip(path)
    assert marker in src, (
        f"Phase J audit fix #6 regression: {relpath} no longer "
        f"consumes the `loading` state from useCluster() (looked for "
        f"`{marker}`). Without it the page renders its 'No Cluster "
        f"Selected' affordance during the legitimate post-deploy "
        f"fetch window, reproducing the original cluster-listing-"
        f"delay bug."
    )


_PAGES_WITH_LOADING_BRANCH = [
    "frontend/src/components/SSLManagement.js",
    "frontend/src/components/Configuration.js",
    "frontend/src/components/DashboardV2.js",
    "frontend/src/components/BulkConfigImport.js",
    "frontend/src/components/BulkVersionHistory.js",
    "frontend/src/components/BackendServers.js",
    "frontend/src/components/FrontendManagement.js",
    "frontend/src/components/ApplyManagement.js",
]


@pytest.mark.parametrize("relpath", _PAGES_WITH_LOADING_BRANCH)
def test_phase_j_page_renders_loading_clusters_branch(relpath):
    """Phase J audit fix #6 — the loading-aware branch must render a
    neutral "Loading clusters…" affordance, not silently swallow the
    case (which would render an entirely blank page during the fetch
    window) and not flip straight to the warning.

    We assert by case-insensitive substring search because Ant Design
    typography variants ("Loading clusters…" with U+2026, "Loading
    clusters..." with three dots, "Loading clusters") all map to the
    same UX. The `clustersLoading` ternary keeps the warning out of
    sight while the fetch is in flight.
    """
    path = _REPO / relpath
    src = _read_or_skip(path)
    assert "clustersLoading" in src, (
        f"Phase J audit fix #6 regression: {relpath} no longer "
        f"references the renamed `clustersLoading` flag. The page "
        f"must use it to gate its 'No Cluster Selected' affordance "
        f"behind `!clustersLoading` so the warning is hidden during "
        f"the legitimate post-deploy fetch window."
    )
    assert re.search(r"Loading\s+clusters", src, flags=re.IGNORECASE), (
        f"Phase J audit fix #6 regression: {relpath} no longer "
        f"renders a 'Loading clusters…' affordance during the "
        f"in-flight cluster fetch. Without it the page goes blank "
        f"between login and the first successful /api/clusters "
        f"response — operators interpret that as a broken page."
    )


# ─────────────────────────────────────────────────────────────────────
# Phase K — Site Wizard validation hardening (Phase A frontend pin)
# ─────────────────────────────────────────────────────────────────────


def test_phase_k_step2_next_blocks_on_https_redirect_with_redirect_rules():
    """Phase K Phase B — the Step 2 Next handler must hard-block when
    `https_redirect=true` and `redirectRules.length > 0`. Pre-Phase-K
    the conflict only surfaced as a warning Alert + a Step 4 toast,
    so operators happily reached Review and were punted back with an
    opaque 422. We pin the gate by asserting the specific guard
    expression is wired into the Step 2 Next branch."""
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    # The Step 2 branch lives inside the Next-button onClick handler;
    # pin both halves of the conjunction and the early-return so a
    # well-meaning refactor that demotes the gate back to a warning
    # can't slip through.
    assert "if (httpsRedirectNow && (aclBuilderData.redirectRules" in src, (
        "Phase K Phase B regression: SiteWizard's Step 2 Next handler "
        "no longer hard-blocks on the https_redirect ⊕ redirect_rules "
        "conflict. Without the block, operators reach Step 4 and only "
        "discover the Pydantic conflict at the final POST."
    )
    assert (
        "HTTP→HTTPS redirect cannot be combined with custom redirect rules"
        in src
    ), (
        "Phase K Phase B regression: the operator-facing Step 2 block "
        "message no longer matches the Pydantic validator's wording, "
        "which makes the resolution path ambiguous."
    )


def test_phase_k_step2_next_blocks_on_tcp_mode_with_https_redirect():
    """Phase K Phase B — same hard-block must catch
    `frontend.mode==='tcp' + https_redirect===true`. This combination
    used to silently produce a config the agent's `haproxy -c`
    rejected only at apply time. Phase A's new
    `reject_tcp_mode_with_https_redirect` validator is the source of
    truth; this UI gate just surfaces it earlier."""
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "if (frontendModeNow === 'tcp' && httpsRedirectNow)" in src, (
        "Phase K Phase B regression: SiteWizard's Step 2 Next handler "
        "no longer blocks the TCP-mode + https_redirect=true "
        "combination. Pydantic's reject_tcp_mode_with_https_redirect "
        "validator (Phase A) catches this at submit, but operators "
        "shouldn't reach Step 4 with a known-bad payload."
    )
    assert "TCP frontends operate at L4" in src, (
        "Phase K Phase B regression: the operator-facing TCP-mode "
        "block message no longer explains why the combination is "
        "invalid (L4 cannot inspect HTTP headers)."
    )


def test_phase_k_aclbuilder_disables_redirect_rules_section_when_https_redirect_on():
    """Phase K Phase B — the Redirect Rules section in
    ACLRuleBuilder must visually disable when the parent passes
    `disableRedirectRules=true`. The flag is wired from
    `watchedHttpsRedirect` in `SiteWizard.js` — both ends pin."""
    builder_path = _REPO / "frontend" / "src" / "components" / "ACLRuleBuilder.js"
    builder_src = _read_or_skip(builder_path)
    assert "disableRedirectRules = false" in builder_src, (
        "Phase K Phase B regression: ACLRuleBuilder no longer accepts "
        "the `disableRedirectRules` prop. The wizard relies on this "
        "prop to grey out the Redirect Rules section when the "
        "https_redirect switch is on."
    )
    assert "aria-disabled={disableRedirectRules" in builder_src, (
        "Phase K Phase B regression: ACLRuleBuilder no longer "
        "exposes `aria-disabled` on the Redirect Rules section. "
        "Screen readers cannot announce the disabled state without "
        "it (a11y best practice)."
    )

    wizard_path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    wizard_src = _read_or_skip(wizard_path)
    assert "disableRedirectRules={!!watchedHttpsRedirect}" in wizard_src, (
        "Phase K Phase B regression: SiteWizard no longer wires "
        "`watchedHttpsRedirect` into ACLRuleBuilder's "
        "`disableRedirectRules` prop. Without this wiring, the "
        "Redirect Rules section stays editable while the switch is "
        "on — an operator can then author the conflict that the "
        "Pydantic validator will reject at submit."
    )


def test_phase_k_https_redirect_switch_disabled_in_tcp_mode():
    """Phase K Phase B — the HTTP→HTTPS redirect Switch must be
    `disabled` when `watchedFrontendMode === 'tcp'`. Plus a
    `useEffect` that auto-clears `https_redirect` to false when the
    operator switches into TCP mode (so a previously-enabled flag
    doesn't get stuck on a TCP frontend). Both pin together."""
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "disabled={watchedFrontendMode === 'tcp'}" in src, (
        "Phase K Phase B regression: the https_redirect Switch is no "
        "longer disabled when the frontend is in TCP mode. Operators "
        "could re-enable a flag the renderer cannot respect at L4."
    )
    assert "watchedFrontendMode === 'tcp' && watchedHttpsRedirect" in src, (
        "Phase K Phase B regression: SiteWizard no longer auto-clears "
        "`https_redirect` when the operator switches into TCP mode. "
        "The TCP-Switch disable alone is insufficient — a flag set "
        "BEFORE the mode change would silently survive into the "
        "submitted payload and get rejected by the Phase A "
        "reject_tcp_mode_with_https_redirect validator."
    )
    assert (
        "form.setFields([\n        { name: ['frontend', 'https_redirect'], value: false },\n      ]);"
        in src
    ) or (
        "form.setFields([{ name: ['frontend', 'https_redirect'], value: false }])"
        in src
    ), (
        "Phase K Phase B regression: the auto-clear effect no longer "
        "uses `form.setFields([{ name: ['frontend','https_redirect'], "
        "value: false }])`. Antd's `setFieldsValue({frontend:{...}})` "
        "shape would replace the entire frontend group, wiping any "
        "in-progress fields the operator had just typed."
    )


def test_phase_k_advanced_tls_collapse_default_closed():
    """Phase K Phase D — the rarely-used HTTPS bind knobs
    (https_bind_port, https_frontend_name_suffix, ssl_alpn,
    ssl_ciphers, ssl_ciphersuites, ssl_strict_sni, ssl_verify)
    must live inside an `advanced-tls` Collapse that defaults to
    closed. This declutters the SSL step for the 99% case while
    keeping the safe-defaults summary visible above.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "Advanced TLS settings" in src, (
        "Phase K Phase D regression: the rarely-used HTTPS bind "
        "knobs are no longer nested under an 'Advanced TLS "
        "settings' Collapse — the SSL step is back to the "
        "11-field flat layout that overwhelmed operators "
        "pre-Phase K."
    )
    assert "key: 'advanced-tls'" in src, (
        "Phase K Phase D regression: the Advanced Collapse no "
        "longer uses key='advanced-tls'. The auto-open logic "
        "below relies on this key to pre-open the Collapse on "
        "draft resume."
    )
    assert "advancedHasNonDefault ? ['advanced-tls'] : []" in src, (
        "Phase K Phase D regression: the Advanced Collapse no "
        "longer auto-opens when a draft has non-default values. "
        "Resumed drafts with custom https_bind_port / ssl_strict_sni "
        "/ ssl_verify would silently hide those values behind the "
        "closed collapse."
    )


def test_phase_k_advanced_tls_collapse_opens_when_draft_has_non_default_values():
    """Phase K Phase D — the auto-open derivation must check the
    fields that changing from default would meaningfully alter
    behaviour: https_bind_port, https_frontend_name_suffix,
    ssl_alpn, ssl_ciphers, ssl_ciphersuites, ssl_strict_sni,
    ssl_verify. Static-source pin asserts every field is part of
    the truthy set so a future addition cannot quietly slip into
    the always-hidden bucket.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    for field, marker in (
        ("https_bind_port", "sslVals.https_bind_port"),
        ("https_frontend_name_suffix", "sslVals.https_frontend_name_suffix"),
        ("ssl_alpn", "sslVals.ssl_alpn"),
        ("ssl_ciphers", "sslVals.ssl_ciphers"),
        ("ssl_ciphersuites", "sslVals.ssl_ciphersuites"),
        ("ssl_strict_sni", "sslVals.ssl_strict_sni"),
        ("ssl_verify", "sslVals.ssl_verify"),
    ):
        assert marker in src, (
            f"Phase K Phase D regression: SSL field `{field}` is no "
            "longer part of the Advanced Collapse auto-open "
            "derivation. A draft with a custom value will silently "
            "hide that value behind the closed Collapse on resume."
        )


def test_phase_k_hsts_preload_switch_disabled_when_prerequisites_unmet():
    """Phase K Phase D — UI parity for the Phase A backend
    `reject_hsts_preload_without_hsts` validator. The `hsts_preload`
    Switch must be disabled until the three preload prerequisites
    are met (HSTS enabled, max-age ≥ 1 year, includeSubDomains).
    Static-source pin asserts the dependency expression ANDs all
    three preconditions.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    # The preload guard is built up as `preloadOk = hstsEnabled &&
    # hstsIncl && typeof hstsMaxAge === 'number' && hstsMaxAge >=
    # 31536000`. Pin each ANDed precondition individually so a
    # refactor that drops one guard is detected.
    for required in (
        "hstsEnabled &&",
        "hstsIncl &&",
        "hstsMaxAge >= 31536000",
    ):
        assert required in src, (
            "Phase K Phase D regression: the hsts_preload Switch's "
            "disable predicate no longer ANDs the precondition "
            f"`{required}`. Operators could re-author the unreachable "
            "preload state the Pydantic validator will reject."
        )
    assert "disabled={!preloadOk}" in src, (
        "Phase K Phase D regression: the hsts_preload Switch is no "
        "longer wired to the `preloadOk` boolean — the disable UX "
        "is gone."
    )


def test_phase_k_ssl_max_ver_validator_rejects_below_min_ver():
    """Phase K Phase D — UI parity for the Phase A backend
    `reject_inverted_tls_versions` validator. The TLS min/max
    Selects must use Antd `dependencies` + a custom validator
    that rejects min > max client-side.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "TLS min version cannot be greater than TLS max version" in src, (
        "Phase K Phase D regression: the TLS min validator no "
        "longer rejects min > max with the parity message. "
        "Operators see the inversion only at submit time as a "
        "Pydantic 422."
    )
    assert "TLS max version cannot be lower than TLS min version" in src, (
        "Phase K Phase D regression: the TLS max validator no "
        "longer rejects max < min with the parity message."
    )
    assert "dependencies={[['ssl', 'ssl_max_ver']]}" in src, (
        "Phase K Phase D regression: the ssl_min_ver Form.Item is "
        "no longer wired to ssl_max_ver via Antd `dependencies`. "
        "Without it the cross-field validator only re-runs when "
        "min itself changes, missing the case where the operator "
        "edits max after min."
    )
    assert "dependencies={[['ssl', 'ssl_min_ver']]}" in src, (
        "Phase K Phase D regression: the ssl_max_ver Form.Item is "
        "no longer wired to ssl_min_ver via Antd `dependencies`."
    )


def test_phase_k_sitewizard_step4_calls_dry_run_with_abort_controller():
    """Phase K Phase C — the SiteWizard must auto-fire the HAProxy
    dry-run on Step 4 entry with an AbortController so a rapid
    Step 4 → Step 2 → Step 4 navigation cancels the in-flight
    request instead of stacking duplicate validations on the
    backend rate limiter.

    Static-source pin asserts:
      * `validate_haproxy_config: true` is sent to /api/sites/preview.
      * An AbortController is constructed AND attached via `signal:`.
      * The Create button's `disabled` clause references the
        dry-run status (`dryRunBlocksSubmit`).
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "validate_haproxy_config: true" in src, (
        "Phase K Phase C regression: SiteWizard's Step 4 effect no "
        "longer enables the dry-run flag on /api/sites/preview. "
        "Without it the operator gets no precommit HAProxy "
        "validation feedback — same UX as before Phase K."
    )
    assert "new AbortController()" in src, (
        "Phase K Phase C regression: SiteWizard no longer "
        "constructs an AbortController for the dry-run effect. "
        "Rapid step navigation will stack pending requests on the "
        "rate-limited /api/sites/preview endpoint."
    )
    assert "signal: controller.signal" in src, (
        "Phase K Phase C regression: SiteWizard's dry-run axios "
        "call no longer wires the AbortController's signal — the "
        "controller exists but cannot actually cancel the in-flight "
        "request."
    )
    assert "dryRunBlocksSubmit" in src, (
        "Phase K Phase C regression: the Create button no longer "
        "references `dryRunBlocksSubmit`. Without it the operator "
        "could click Create while errors are rendered in the "
        "validation card. (Phase K Phase D removed the second "
        "Create-as-PENDING button — only the unified Create button "
        "remains.)"
    )


def test_phase_k_sitewizard_step4_renders_pydantic_error_state():
    """Phase K Phase C — the dry-run catch must branch on
    `error?.response?.status === 422` and store the FastAPI
    `detail[*]` array for the validation card to render with
    Edit-Step jumpbacks. This is the operator-facing UX that
    catches PEM-stripped resume drafts (`ssl.mode='upload' +
    certificate_content=""`) and the new
    `reject_tcp_mode_with_https_redirect` validator from Phase A.

    Static-source pin on:
      * 422 branch in the catch block.
      * `pydantic_error` status state on `dryRunResult`.
      * `_locPathToStep` projection (loc → step) used by the card
        for jump-back buttons.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "status === 422" in src, (
        "Phase K Phase C regression: the dry-run catch no longer "
        "branches on HTTP 422. PEM-stripped resume drafts and "
        "Phase A cross-field validator failures will render as "
        "generic `unavailable` instead of the operator-facing "
        "`pydantic_error` panel with Edit-Step jumpbacks."
    )
    assert "'pydantic_error'" in src, (
        "Phase K Phase C regression: SiteWizard no longer keeps a "
        "`pydantic_error` status state — the validation card has "
        "no way to render FastAPI body-parse failures with "
        "field-level guidance."
    )
    assert "_locPathToStep" in src, (
        "Phase K Phase C regression: SiteWizard no longer projects "
        "FastAPI loc[] to a wizard step. Operators see the error "
        "text but lose the one-click Edit-Step-N jumpback path."
    )


def test_phase_k_aclrulebuilder_serializes_to_string():
    """Phase K Phase A — `ACLRuleBuilder` must keep emitting `string[]`
    for `aclRules`, `useBackendRules`, `redirectRules`. The Pydantic
    contract on `FrontendStep` is now `List[str]` /
    `List[Union[str, dict]]`; if a future refactor switches the
    builder back to dict emission for ACL or use_backend the wizard
    will resurrect the
        body -> frontend -> acl_rules -> 0:
            Input should be a valid dictionary
    422 the user originally reported.

    Static-source pin: each `serialize*Rule` helper returns either a
    string literal, a string template, or `rule.raw` (which the rest
    of the builder guarantees is a string when set). We assert by
    locating the function bodies and confirming there is no
    `return { … }` / `return [` shape inside.
    """
    path = _REPO / "frontend" / "src" / "components" / "ACLRuleBuilder.js"
    src = _read_or_skip(path)
    for fn_name in ("serializeAclRule", "serializeUseBackendRule", "serializeRedirectRule"):
        match = re.search(
            rf"function\s+{fn_name}\s*\([^)]*\)\s*\{{(.*?)\n\}}",
            src,
            flags=re.DOTALL,
        )
        assert match, (
            f"Phase K regression: {fn_name} not found in ACLRuleBuilder.js. "
            "The wizard's submit contract is `string[]`; if the builder "
            "stops exposing a string-returning serializer the wizard will "
            "regress to the original 422 'Input should be a valid dictionary' "
            "error operators reported pre-Phase K."
        )
        body = match.group(1)
        assert "return {" not in body, (
            f"Phase K regression: {fn_name} now returns a dict / object. "
            "The Pydantic `FrontendStep` contract requires string elements "
            "for `acl_rules` / `use_backend_rules` (and accepts string OR "
            "dict for `redirect_rules` only). A dict-returning builder will "
            "trigger the original 422 error operators reported pre-Phase K."
        )
        assert (
            "return rule.raw" in body
            or "return ''" in body
            or "return `" in body
            or "return str" in body
            or "return backend" in body  # serializeUseBackendRule short-path
        ), (
            f"Phase K regression: {fn_name} no longer returns a string. "
            "The wizard's submit contract is `string[]`; the function must "
            "produce HAProxy directive strings for the wizard POST to clear "
            "Pydantic validation."
        )


def test_phase_k_sitewizard_resets_dry_run_status_when_leaving_step4():
    """Phase K Phase C audit-fix — when the operator navigates AWAY
    from Step 4, the wizard must reset `dryRunResult.status` back to
    `'idle'`. Otherwise a stale `clean` / `errors` / `warnings_only`
    state survives across a Step-2 ACL edit (the ACL builder lives
    OUTSIDE the antd Form so its mutations do not fire
    `onValuesChange`) and the auto-fire effect's
    `if (dryRunResult.status !== 'idle') return undefined;` branch
    suppresses the next fetch when the operator returns to Step 4.

    Operator-visible symptom: after editing redirect / ACL rules on
    Step 2 the wizard would render YESTERDAY'S validation card on
    re-entry, even though the rules just changed. The "Create" button
    would be enabled / disabled based on the stale status. Plan's
    Phase E manual checklist item 12 ("Step 4 → Step 2 → Step 4
    within 200 ms → no duplicate dry-run requests") explicitly
    requires re-firing on every Step 4 entry, not "first entry only".

    Static-source pin: assert the `step !== WIZARD_LAST_STEP` branch
    explicitly reasserts `status: 'idle'` (not just aborts the
    in-flight controller). The pin walks the Step-4 effect body so a
    refactor that drops the reset is detected immediately.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    # Locate the dry-run effect by anchoring on the comment that
    # introduces it; this is more robust than matching the bare
    # `useEffect((` boilerplate that appears many times in the file.
    anchor = "// Phase K Phase C: auto-fire the HAProxy dry-run validation"
    eff_start = src.find(anchor)
    assert eff_start >= 0, (
        "Phase K Phase C regression: the dry-run useEffect anchor "
        "comment is missing — SiteWizard no longer documents the "
        "auto-fire effect."
    )
    # Extract the effect body up to the closing dependency array.
    # Phase K Phase C audit-fix #3: deps no longer include
    # `dryRunResult.status` (that was the self-cancel race root cause
    # — see the long-form comment around `dryRunStatusRef` /
    # `dryRunInvalidationTick` in SiteWizard.js for the full
    # explanation). The new deps are
    # `[step, form, aclBuilderData, dryRunInvalidationTick]`.
    eff_end = src.find(
        "[step, form, aclBuilderData, dryRunInvalidationTick]",
        eff_start,
    )
    assert eff_end >= 0, (
        "Phase K Phase C regression: the dry-run useEffect's "
        "dependency array no longer matches "
        "`[step, form, aclBuilderData, dryRunInvalidationTick]`. "
        "Audit-fix #3 removed `dryRunResult.status` from deps to "
        "kill the self-cancel race (the cleanup of the prior run "
        "aborted the in-flight fetch when `setStatus('loading')` "
        "re-triggered the effect — visible as the wizard sitting on "
        "'Validating against HAProxy…' indefinitely). The "
        "`dryRunInvalidationTick` counter is the external re-trigger "
        "channel used by onValuesChange instead."
    )
    effect_body = src[eff_start:eff_end]
    # The cleanup branch (step !== 4) must reset to `idle` so a Step 2
    # ACL edit + Step 4 return triggers a fresh fetch. Pin both the
    # control-flow guard AND the status reset itself.
    assert "step !== WIZARD_LAST_STEP" in effect_body, (
        "Phase K Phase C audit-fix regression: the dry-run useEffect "
        "no longer guards on `step !== WIZARD_LAST_STEP` to detect "
        "the leave-Step-4 path."
    )
    assert "status: 'idle'" in effect_body, (
        "Phase K Phase C audit-fix regression: the leave-Step-4 "
        "branch no longer resets `dryRunResult.status` to 'idle'. "
        "Without the reset, a stale `clean` / `errors` / "
        "`warnings_only` state survives across an ACL-builder edit "
        "on Step 2 (the builder lives outside antd's Form, so its "
        "mutations do NOT fire `onValuesChange` invalidation), and "
        "the auto-fire branch suppresses the next fetch on return "
        "to Step 4 — operators see yesterday's validation card."
    )
    # Phase K Phase C audit-fix #3: the leave-Step-4 reset must use
    # the REF (dryRunStatusRef.current) not the closure-captured
    # state, otherwise the ref-based deps cannot detect the stale
    # status on re-entry. Pin the ref usage explicitly so a future
    # refactor that drops the ref read regresses the race fix.
    assert "dryRunStatusRef.current" in effect_body, (
        "Phase K Phase C audit-fix #3 regression: the dry-run "
        "useEffect no longer reads from `dryRunStatusRef.current`. "
        "Audit-fix #3 made the effect ref-driven so it does NOT "
        "re-run on internal status changes (that was the self-"
        "cancel race). Without the ref read the effect cannot "
        "guard 'already loading / completed' correctly and we get "
        "duplicate fetches or — worse — the stuck 'Validating "
        "against HAProxy…' state from before the fix."
    )


def test_phase_k_sitewizard_pydantic_jumpback_falls_back_to_msg_for_root_errors():
    """Phase K Phase C audit-fix #2 — the validation card's
    "Edit Step N" jump-back button must work for SiteCreate-level
    `model_validator(mode="after")` errors.

    Pydantic v2 raises root-level model_validator errors with
    `loc=()` (empty tuple). FastAPI wraps the response, prepending
    `'body'` so the operator-visible 422 envelope is
    `loc=['body']` — length 1. The legacy `_locPathToStep`
    early-returned `null` whenever `loc.length < 2`, so:

      * PEM-stripped resume → "ssl.mode='upload' requires a non-
        empty PEM-encoded certificate_content (if you resumed a
        draft, PEM fields were stripped …)" → no Edit-Step
        button. Plan satır 148, 234 explicitly require Step 3
        jumpback for this exact flow.
      * `enforce_acme_apply_and_http` ACME cross-field hatalarının
        tümü `loc=['body']` formatında → none of them got a
        jumpback, defeating Step 4's "fix-from-here" UX promise.

    The fix routes the message text through a small ordered
    pattern table (SSL → frontend → backend → cluster/domains →
    review) when `loc` cannot pinpoint a step on its own.

    This pin asserts:
      1. The pattern table exists and is documented.
      2. `_locPathToStep` accepts a `msg` second arg.
      3. The render call site forwards `p.msg` so the fallback
         actually fires.
      4. The patterns cover the four user-visible failure
         categories the plan calls out (PEM, frontend, backend,
         domains/cluster) so a refactor that prunes one is
         caught.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)

    assert "PYDANTIC_MSG_TO_STEP_PATTERNS" in src, (
        "Phase K Phase C audit-fix #2 regression: the message-"
        "content pattern table for SiteCreate-level Pydantic "
        "errors is missing. Without it, root-level model_validator "
        "errors land with `loc=['body']` and the wizard cannot "
        "compute the target step for the Edit-Step jump-back "
        "button — most importantly the PEM-stripped resume flow "
        "loses its Step 3 jump-back."
    )
    assert "function _locPathToStep(loc, msg)" in src, (
        "Phase K Phase C audit-fix #2 regression: "
        "`_locPathToStep` no longer takes a `msg` argument, so "
        "the message-content fallback cannot fire even if the "
        "pattern table is present."
    )
    assert "_locPathToStep(p.loc, p.msg)" in src, (
        "Phase K Phase C audit-fix #2 regression: the pydantic "
        "error renderer no longer forwards `p.msg` to "
        "`_locPathToStep`. Without the message text the fallback "
        "patterns can't fire and PEM-stripped resume flows lose "
        "their Step 3 jump-back button."
    )
    # Verify the four operator-visible categories are still
    # represented. Each marker must appear inside the patterns
    # table so a refactor that drops a step's coverage is caught.
    table_start = src.find("PYDANTIC_MSG_TO_STEP_PATTERNS = [")
    table_end = src.find("];", table_start)
    assert table_start >= 0 and table_end >= 0, (
        "Phase K Phase C audit-fix #2 regression: pattern table "
        "delimiters are missing or malformed."
    )
    table_body = src[table_start:table_end]
    for marker, label in (
        ("PEM", "SSL/PEM-stripped resume routing to Step 3"),
        ("frontend\\.", "frontend-field routing to Step 2"),
        ("backend\\.", "backend-field routing to Step 1"),
        ("domains", "cluster/domains routing to Step 0"),
        ("apply_immediately", "review-step routing to Step 4"),
    ):
        assert marker in table_body, (
            f"Phase K Phase C audit-fix #2 regression: "
            f"`{label}` is no longer covered by the message-"
            f"content pattern table — operators will not get a "
            f"jump-back button for this category of error."
        )


def test_phase_k_sitewizard_pydantic_pattern_order_routes_acme_xfield_correctly():
    """Phase K Phase C audit-fix #2 (round 3) — the pattern table
    must be ordered so cross-field ACME errors route to the step
    the operator must EDIT to fix the error, not the step that
    "feels related".

    `enforce_acme_apply_and_http` raises messages like:

      * "ssl.mode='acme' requires apply_immediately=true …"
        → operator fix is on Step 4 (toggle apply_immediately),
        NOT Step 3 (the operator chose acme on purpose).
      * "ssl.mode='acme' requires frontend.mode='http' …"
        → operator fix is on Step 2 (FE mode), NOT Step 3.
      * "ssl.mode='acme' requires frontend.bind_port=80 …"
        → operator fix is on Step 2 (FE bind_port), NOT Step 3.
      * "ssl.mode='acme' (HTTP-01) cannot issue wildcard certs
        (*.example.com). …"
        → operator fix is on Step 0 (remove wildcard) OR Step 3
        (switch ssl.mode); Step 0 is the more direct path.

    A naive ordering ("SSL first because every message starts
    with ssl.mode='acme'") would route every cross-field hit to
    Step 3, defeating the jump-back's "fix-from-here" promise.
    The fix is to put MORE-SPECIFIC actionable markers
    (apply_immediately → wildcard/domains → frontend.* →
    backend.*) BEFORE the general SSL catch-all.

    Static-source pin: read the pattern table in source order
    and assert the SSL catch-all (the entry that matches
    `ssl\\.`) is the LAST entry. Plus assert
    `apply_immediately` appears at the head of the table.
    Without this ordering, the audit-fix #2 jump-back regresses
    silently for every ACME cross-field error.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    table_start = src.find("PYDANTIC_MSG_TO_STEP_PATTERNS = [")
    table_end = src.find("];", table_start)
    assert table_start >= 0 and table_end >= 0, (
        "Pattern table delimiters missing — earlier pin should "
        "have caught this."
    )
    table_body = src[table_start:table_end]
    # Pull out lines that contain a regex literal opener `[/`. We
    # want to inspect ONLY actual pattern entries, not comment
    # lines that mention `ssl\.` etc.
    regex_lines = [ln for ln in table_body.splitlines() if "[/" in ln]
    assert regex_lines, (
        "Phase K Phase C audit-fix #2 round 3 regression: no "
        "regex literals found in pattern table — the table is "
        "empty or malformed."
    )

    def _step_of(line):
        # Each entry is `  [/.../i, N],` — extract the trailing N.
        # The line ends with `, N],` (single closing bracket for
        # the tuple `[regex, step]`).
        import re
        m = re.search(r",\s*(\d+)\s*\]\s*,?\s*$", line)
        if not m:
            return None
        return int(m.group(1))

    line_steps = [(line, _step_of(line)) for line in regex_lines]

    # The LAST regex line must be the SSL catch-all. Identifying
    # the SSL catch-all: it routes to step 3 AND its pattern
    # text mentions `ssl\.` (the catch-all SSL token).
    last_line, last_step = line_steps[-1]
    assert last_step == 3 and "ssl\\." in last_line, (
        "Phase K Phase C audit-fix #2 round 3 regression: the "
        "LAST entry in PYDANTIC_MSG_TO_STEP_PATTERNS is no "
        "longer the SSL catch-all (step 3 + `ssl\\.` token). "
        "The SSL pattern must come LAST so it does not match "
        "BEFORE more-specific markers (apply_immediately, "
        "wildcard, frontend.*) for cross-field ACME errors. "
        f"Actual last entry: step={last_step}, line={last_line!r}"
    )

    # Build the order of step routes as they appear in source.
    # Then assert specific markers come BEFORE the SSL catch-all.
    step_order = [step for _, step in line_steps]
    ssl_pos = len(step_order) - 1  # last entry by construction above

    # apply_immediately must route to step 4 and appear BEFORE SSL.
    apply_lines = [
        i for i, line in enumerate(regex_lines)
        if "apply_immediately" in line
    ]
    assert apply_lines, (
        "Phase K Phase C audit-fix #2 round 3 regression: "
        "`apply_immediately` regex literal missing — "
        "'ssl.mode=\"acme\" requires apply_immediately=true' "
        "loses its Step 4 jump-back."
    )
    assert apply_lines[0] < ssl_pos, (
        "Phase K Phase C audit-fix #2 round 3 regression: the "
        "`apply_immediately` pattern appears AT/AFTER the SSL "
        "catch-all in source order. Cross-field error "
        "'ssl.mode=\"acme\" requires apply_immediately=true' "
        "will be mis-routed to Step 3 instead of Step 4."
    )

    # frontend.* must route to step 2 and appear BEFORE SSL.
    fe_lines = [
        i for i, line in enumerate(regex_lines)
        if "frontend\\." in line
    ]
    assert fe_lines, (
        "Phase K Phase C audit-fix #2 round 3 regression: "
        "`frontend\\.` regex literal missing."
    )
    assert fe_lines[0] < ssl_pos, (
        "Phase K Phase C audit-fix #2 round 3 regression: the "
        "`frontend\\.` regex line appears AT/AFTER the SSL "
        "catch-all in source order. Cross-field errors like "
        "'ssl.mode=\"acme\" requires frontend.mode=\"http\"' or "
        "'ssl.mode=\"acme\" requires frontend.bind_port=80' "
        "will be mis-routed to Step 3 instead of Step 2."
    )

    # wildcard must route to step 0 and appear BEFORE SSL.
    wc_lines = [
        i for i, line in enumerate(regex_lines)
        if "wildcard" in line
    ]
    assert wc_lines, (
        "Phase K Phase C audit-fix #2 round 3 regression: "
        "`wildcard` regex literal missing."
    )
    assert wc_lines[0] < ssl_pos, (
        "Phase K Phase C audit-fix #2 round 3 regression: the "
        "`wildcard` regex line appears AT/AFTER the SSL "
        "catch-all in source order. The wildcard-ACME error "
        "will be mis-routed to Step 3 instead of Step 0."
    )


def test_phase_k_sitewizard_pydantic_error_render_skips_empty_field_path():
    """Phase K Phase C audit-fix #2 round 4 — the pydantic_error
    list item must NOT render a stray `<strong>: </strong>`
    prefix when the failing error has no field path.

    Pydantic v2 raises SiteCreate-level model_validator errors
    with `loc=()`; FastAPI prepends `'body'` so the envelope
    becomes `loc=['body']` (length 1). The renderer takes
    `p.loc.slice(1)` to drop the leading 'body' marker — for
    length-1 locs that yields `[]` → `join('.')` → empty
    string. The legacy renderer then dropped that empty string
    inside `<strong>{...}: </strong>`, producing a visually
    awkward "  : Value error, ssl.mode='upload' requires …"
    string-with-orphan-colon for every PEM-stripped resume
    error and every `enforce_acme_apply_and_http` cross-field
    rejection (which is, per audit-fix #2, the entire reason
    the renderer cares about loc=['body'] in the first place).

    The fix conditionally renders the strong/colon prefix
    ONLY when `p.loc.length > 1`. This pin asserts the guard
    is in place by walking the renderer source and verifying:

      1. The `fieldPath` const is computed from `p.loc.length
         > 1` (i.e. a length check, not unconditional).
      2. The strong tag wraps `fieldPath` (the new, computed
         value) — not the legacy unconditional
         `p.loc.slice(1).join('.')` literal.
      3. The strong tag is rendered only when `fieldPath` is
         truthy ({fieldPath && (<strong>...</strong>)}).
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)

    # 1. The length-aware fieldPath const must exist.
    assert "p.loc.length > 1" in src, (
        "Phase K Phase C audit-fix #2 round 4 regression: the "
        "renderer no longer guards on `p.loc.length > 1` before "
        "computing the field path prefix. SiteCreate-level "
        "model_validator errors (`loc=['body']`) will once "
        "again render with a stray `: ` orphan colon."
    )
    # 2. The fieldPath const must be the actual joined path.
    assert "fieldPath" in src, (
        "Phase K Phase C audit-fix #2 round 4 regression: the "
        "`fieldPath` const that holds the joined Pydantic loc "
        "is missing — the cosmetic guard was reverted."
    )
    # 3. The strong tag must be rendered only when fieldPath
    #    is truthy. Match a tolerant pattern so whitespace /
    #    line breaks in the source do not break the pin.
    import re
    guard_pattern = re.compile(
        r"\{\s*fieldPath\s*&&\s*\(\s*<strong>",
        re.MULTILINE,
    )
    assert guard_pattern.search(src), (
        "Phase K Phase C audit-fix #2 round 4 regression: the "
        "strong tag wrapping the field path is no longer "
        "guarded by `{fieldPath && (...)}`. PEM-stripped resume "
        "errors and other `loc=['body']` rejections will render "
        "with an empty-prefix orphan colon."
    )


# ---------------------------------------------------------------------------
# Phase K Phase D — Site Wizard UX simplifications (Bulgu #1/#2/#5/#6).
# ---------------------------------------------------------------------------


def test_phase_k_phase_d_sitewizard_uses_cluster_context_for_step0():
    """Phase K Phase D (Bulgu #1) — the wizard must consume the same
    header `ClusterContext` that every other entity page reads from.

    Pre-fix Step 0 had its own cluster Select dropdown decoupled from
    the global header cluster picker. Operators could (and did) pick
    cluster A in the header, start the wizard, then choose cluster B
    on Step 0 with NO visual indication that they had drifted off
    the header cluster. The fix:

      1. Imports `useCluster` from `../contexts/ClusterContext`.
      2. Hooks the wizard component into `useCluster()` to obtain
         `selectedCluster`, the cluster list (for resume sync), and
         `selectCluster` (for resume-driven swap).
      3. Replaces the Step 0 cluster `<Select>` with a read-only
         `<Tag>` display + hidden Form.Item (so submit / watch /
         per-cluster fetches still see the value).
      4. Auto-syncs `form.cluster_id` from `selectedCluster.id` via a
         useEffect so mid-wizard header changes propagate.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "from '../contexts/ClusterContext'" in src, (
        "Phase K Phase D (Bulgu #1) regression: SiteWizard no "
        "longer imports `useCluster` from ClusterContext. Step 0's "
        "cluster picker will fall out of sync with the header again."
    )
    assert "useCluster()" in src, (
        "Phase K Phase D (Bulgu #1) regression: SiteWizard no "
        "longer calls `useCluster()`. The wizard cannot honour the "
        "header cluster selection."
    )
    # Step 0's Form.Item for cluster_id must be `hidden` now (the
    # value lives in form state for the submit payload AND for the
    # `watchedClusterId`-keyed fetches, but the visible UI is the
    # read-only Tag below it).
    import re
    hidden_field = re.compile(
        r'name="cluster_id"\s*\n\s*hidden',
        re.MULTILINE,
    )
    assert hidden_field.search(src), (
        "Phase K Phase D (Bulgu #1) regression: Step 0's cluster_id "
        "Form.Item is no longer `hidden`. Operators will see a "
        "second cluster picker that contradicts the header."
    )
    assert "selectedCluster.id" in src, (
        "Phase K Phase D (Bulgu #1) regression: the wizard no "
        "longer reads `selectedCluster.id` to sync form.cluster_id "
        "from the header context."
    )


def test_phase_k_phase_d_sitewizard_filters_ca_bundle_by_usage_type():
    """Phase K Phase D (Bulgu #2) — the per-server "CA bundle for
    upstream verification" Select must filter to certs with
    `usage_type === 'server'` (mirroring BackendServers.js:221's
    `&usage_type=server` query param). Pre-fix the wizard surfaced
    every cert in the cluster regardless of usage, so an operator
    could pick a frontend (HTTPS-bind) cert as a CA bundle and the
    resulting `ca-file` line would parse-error at agent apply.

    The SSL & ACME step's "Existing certificate" Select gets the
    inverse filter: `usage_type === 'frontend'`, matching the HTTPS
    bind contract.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "c.usage_type === 'server'" in src, (
        "Phase K Phase D (Bulgu #2) regression: the per-server CA "
        "bundle Select no longer filters to `usage_type='server'`. "
        "Operators can once again pick a frontend cert and the "
        "resulting `ca-file` will fail at apply time."
    )
    assert "c.usage_type === 'frontend'" in src, (
        "Phase K Phase D (Bulgu #2) regression: the SSL & ACME "
        "step's existing-certificate Select no longer filters to "
        "`usage_type='frontend'`. Operators could pick a server-"
        "side CA bundle for the HTTPS bind and HAProxy would "
        "parse-error on `unable to load SSL private key`."
    )


def test_phase_k_phase_d_orphan_detect_short_circuits_during_cert_fetch():
    """Phase K Phase D (Bulgu #5 part 1) — the orphan-detect effect
    must short-circuit while `existingCertsLoading=true`. Pre-fix the
    effect ran on the SAME render that the resume effect's
    setFieldsValue committed the new cluster_id; existingCerts was
    still empty (fetch in flight) so the resumed ssl_certificate_id
    looked like an orphan and got wiped. Operator returned to Step 3
    to find an empty Select.

    Pin: the effect body's early-return check on
    `existingCertsLoading`, and the deps array now includes
    `existingCertsLoading` so the effect re-runs when the fetch
    settles.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "if (existingCertsLoading) return;" in src, (
        "Phase K Phase D (Bulgu #5) regression: the orphan-detect "
        "effect no longer short-circuits while the cert fetch is "
        "in flight. A resumed draft's ssl_certificate_id will be "
        "wiped before the cert list has a chance to load."
    )
    # Bulgu #14 widened this dep array to include `step` and
    # `resumedFromDraft` so the orphan-clear can ALSO bounce the
    # operator back to Step 3 when the clear happened on Step 5.
    # The original Bulgu #5 invariant — `existingCertsLoading`
    # must be in the deps so the effect re-fires when the fetch
    # settles — is what this pin is really protecting. Match the
    # core deps as a substring so future legitimate widenings
    # don't accidentally fail this test.
    assert "existingCerts, existingCertsLoading, watchedClusterId, form" in src, (
        "Phase K Phase D (Bulgu #5) regression: the orphan-detect "
        "deps array no longer includes `existingCertsLoading`. The "
        "short-circuit guard works on the first run but the effect "
        "would never re-evaluate when the fetch settles."
    )


def test_phase_k_phase_d_sitewizard_single_submit_button():
    """Phase K Phase D (Bulgu #6) — the wizard must expose only ONE
    submit button. Pre-fix there were two:

      * "Create as PENDING" → apply_immediately=false (operators
        thought this was a separate code path; it was redundant
        with "queue this for Apply Management").
      * "Create & Apply" → apply_immediately=true (bypassed the
        standard PENDING → Apply Management → operator-click flow).

    The unified button is labelled "Create Site" (or "Create &
    Apply (ACME)" when sslMode='acme', because ACME forces the
    immediate apply for the HTTP-01 challenge). `handleSubmit`
    derives apply_immediately from sslMode automatically — no
    button-driven branching.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    # The 'Create as PENDING' STRING may appear in historical
    # comments / removal notes that document Phase K Phase D.
    # What MUST NOT survive is the actual button JSX. We pin the
    # button element shape (an antd Button whose visible text is
    # "Create as PENDING") rather than the bare string so the
    # phrase remains free to appear in explanatory comments.
    import re
    button_pattern = re.compile(
        r"<Button[^>]*>\s*Create as PENDING\s*</Button>",
        re.DOTALL,
    )
    assert not button_pattern.search(src), (
        "Phase K Phase D (Bulgu #6) regression: the 'Create as "
        "PENDING' <Button> element is back. It bypasses the "
        "standard manual-flow convention (entity Create → PENDING "
        "version → Apply Management review → operator Apply). "
        "Operators were confused by two buttons; unified flow "
        "re-introduces the confusion."
    )
    assert "submitButtonLabel" in src, (
        "Phase K Phase D (Bulgu #6) regression: the unified submit "
        "button no longer derives its label from the SSL mode. "
        "Static label loses the explicit signal to the operator "
        "that ACME forces apply."
    )
    # The handler must auto-derive apply_immediately from sslMode.
    assert "effectiveApply" in src, (
        "Phase K Phase D (Bulgu #6) regression: handleSubmit no "
        "longer derives apply_immediately from the SSL mode "
        "(`effectiveApply`). The button-driven branching is back, "
        "which was the source of the Bulgu #6 confusion."
    )


def test_phase_k_phase_d_dry_run_uses_ref_pattern():
    """Phase K Phase D (Bulgu #3/#5 part 2) — the stuck-loading
    state was caused by the dry-run useEffect having
    `dryRunResult.status` in its dep array AND calling
    `setDryRunResult({status: 'loading'})` at the top of its body.
    The status change re-triggered the effect; the cleanup of the
    previous run aborted the in-flight fetch; the new body returned
    early; the aborted fetch's catch returned without setting state;
    status stayed 'loading' forever.

    Fix: shadow status in `dryRunStatusRef`, drive external re-
    triggers via `dryRunInvalidationTick`, remove status from deps.
    Pin both the ref and the tick state to defend the fix.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "dryRunStatusRef" in src, (
        "Phase K Phase D (Bulgu #3) regression: `dryRunStatusRef` "
        "is gone. Without the ref, the dry-run useEffect would "
        "have to read `dryRunResult.status` (closure) or include "
        "it in deps (self-cancel race). Either way the stuck-"
        "loading bug returns."
    )
    assert "dryRunInvalidationTick" in src, (
        "Phase K Phase D (Bulgu #3) regression: "
        "`dryRunInvalidationTick` is gone. Without the external "
        "re-trigger channel, onValuesChange invalidations on "
        "Step 4 (e.g. toggling Apply Immediately) would never "
        "re-fire the dry-run because status is no longer in deps."
    )
    # The onValuesChange handler must bump the tick when invalidating.
    assert "setDryRunInvalidationTick" in src, (
        "Phase K Phase D (Bulgu #3) regression: onValuesChange no "
        "longer bumps `dryRunInvalidationTick` to re-trigger the "
        "dry-run after invalidation. Without the bump, operators "
        "would see a stale 'idle' state on Step 4 with no fresh "
        "validation card."
    )


def test_phase_k_phase_d_preview_response_includes_full_field_set():
    """Phase K Phase D (Bulgu #4) — the /api/sites/preview response
    must echo every operator-customisable field that affects the
    persisted entity / generated HAProxy config. Pre-fix the
    SiteDrafts Preview modal showed only a sparse subset (name,
    bind, mode, etc.) so an operator who set per-server timings,
    backend cookie persistence, frontend maxconn, HSTS, or
    ciphersuites had no visibility on whether those values would
    actually be applied.

    Pin a few representative additive fields to ensure no future
    refactor drops them silently.
    """
    path = _REPO / "backend" / "routers" / "site_wizard.py"
    src = _read_or_skip(path)
    for field in (
        '"cookie_name"',
        '"timeout_connect"',
        '"timeout_server"',
        '"max_connections"',
        '"check_port"',
        '"maxconn"',
        '"timeout_client"',
        '"compression_enabled"',
        '"acl_rules_count"',
        '"use_backend_rules_count"',
        '"ssl_ciphersuites"',
    ):
        assert field in src, (
            f"Phase K Phase D (Bulgu #4) regression: /api/sites/"
            f"preview no longer echoes {field}. The SiteDrafts "
            "Preview modal loses parity with what create_site "
            "actually persists, defeating the modal's purpose "
            "(audit before Apply Management)."
        )


def test_phase_k_phase_d_resume_pins_cluster_ref_before_setFieldsValue():
    """Phase K Phase D (Bulgu #5) — the resume effect must update
    `prevClusterRef.current` BEFORE `form.setFieldsValue(merged)`.
    Otherwise the cluster-transition cleanup effect (triggered by
    the form-driven `watchedClusterId` re-evaluating to the new
    draft value on the next render) misreads the hydration as
    "operator switched clusters" and wipes ssl_certificate_id /
    per-server CA bundle ids.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    # Locate the resume effect body and assert the ordering: the
    # `prevClusterRef.current = merged.cluster_id;` write must
    # appear BEFORE the `form.setFieldsValue(merged);` call.
    anchor = "// Phase K Phase D (Bulgu #1): pin the cluster change-detection"
    block_start = src.find(anchor)
    assert block_start >= 0, (
        "Phase K Phase D (Bulgu #5) regression: the resume effect "
        "no longer documents the pre-setFieldsValue prevClusterRef "
        "pin. Without that pin a resumed cluster_id hydration "
        "triggers the transition cleanup and wipes cert ids."
    )
    setfields = src.find("form.setFieldsValue(merged);", block_start)
    pin = src.find("prevClusterRef.current = merged.cluster_id;", block_start)
    assert 0 <= pin < setfields, (
        "Phase K Phase D (Bulgu #5) regression: `prevClusterRef."
        "current = merged.cluster_id;` no longer fires BEFORE "
        "`form.setFieldsValue(merged);`. The cluster-transition "
        "cleanup effect will once again wipe the resumed "
        "ssl_certificate_id."
    )


def test_phase_k_phase_d_resume_cluster_swap_race_fix():
    """Phase K Phase D (Bulgu #7) — on a COLD mount where
    ClusterContext loads AFTER the resume effect ran (browser
    refresh of /sites/new with sessionStorage already populated by
    a previous Resume click), the header sync effect must prefer
    PUSHING the header to the draft's cluster_id rather than
    overwriting `form.cluster_id` with the (different) default
    cluster.

    Pin:
      * `resumeClusterSynced` state exists.
      * Header sync effect uses a one-shot swap branch keyed on
        `resumedFromDraft && !resumeClusterSynced` that calls
        `selectClusterRef.current(...)`.
      * `selectClusterRef` is declared (so the dep set stays
        small and we avoid spurious re-runs on every
        ClusterProvider render).
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    assert "const selectClusterRef = useRef(selectCluster);" in src, (
        "Phase K Phase D (Bulgu #7) regression: `selectClusterRef` "
        "is no longer derived from `selectCluster` via useRef. "
        "Without the ref the header sync effect either re-runs "
        "on every ClusterProvider render OR re-introduces the "
        "resume-vs-context race that wipes draft cluster ids."
    )
    assert "const [resumeClusterSynced, setResumeClusterSynced] = useState(false);" in src, (
        "Phase K Phase D (Bulgu #7) regression: the "
        "`resumeClusterSynced` one-shot gate has been removed. "
        "Without it the post-resume swap can either fire forever "
        "(loop) or never (race)."
    )
    assert "resumedFromDraft &&" in src and "!resumeClusterSynced" in src, (
        "Phase K Phase D (Bulgu #7) regression: the header sync "
        "effect no longer gates the post-resume swap on "
        "`resumedFromDraft && !resumeClusterSynced`. Manual "
        "header changes post-resume will silently revert to the "
        "draft cluster (or vice versa)."
    )
    assert "selectClusterRef.current(draftCluster)" in src, (
        "Phase K Phase D (Bulgu #7) regression: the post-resume "
        "swap no longer calls `selectClusterRef.current(...)`. "
        "Either the import path is broken or the ref pattern "
        "regressed back to using `selectCluster` directly "
        "(unstable dep)."
    )


def test_phase_k_phase_d_wizard_preserves_form_state_across_step_navigation():
    """Phase K Phase D follow-up (Bulgu #11) — the Site Wizard
    MUST preserve every operator-entered Form.Item value across
    Previous / Next clicks. The architecture that delivers this
    contract:

      1. All step contents stay MOUNTED at all times — only the
         CSS `display` toggles between `block` (active step) and
         `none` (inactive). React does NOT unmount the children,
         so Antd's Form.Item registrations stay intact.
      2. Form does NOT set `preserve={false}` — the Antd default
         (`true`) keeps values in form state even when a
         conditionally-rendered Form.Item unmounts (e.g.
         `<Form.Item shouldUpdate>` branches in the SSL & ACME
         step that swap between `upload`, `existing`, `acme`,
         `none` content).
      3. No Form.Item sets `preserve={false}` individually either.

    This pin enforces (1)-(3) so a future refactor cannot
    accidentally regress to per-step conditional rendering or
    a `preserve={false}` slip that silently wipes operator
    work on every Previous click.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)

    # Architecture #1 — all steps mounted, display:none toggle.
    assert "stepContents.map((s, idx) =>" in src, (
        "Bulgu #11 architectural pin: the wizard MUST render every "
        "step content in a single .map() pass. Removing this pattern "
        "in favour of `step === 0 ? ... : null` style conditional "
        "rendering would unmount inactive steps and Antd would lose "
        "field registrations on every navigation."
    )
    assert "display: step === idx ? 'block' : 'none'" in src, (
        "Bulgu #11 architectural pin: the active-step toggle MUST "
        "be a CSS `display` switch, NOT an `if (step === idx)` "
        "conditional return. Conditional return unmounts the step "
        "div and the Form.Items inside it; values then survive only "
        "via Antd's `preserve=true` default and re-mount initialValue "
        "races become possible."
    )

    # Architecture #2/#3 — no preserve={false}.
    assert "preserve={false}" not in src, (
        "Bulgu #11 form-state pin: no Form / Form.Item in the wizard "
        "may set `preserve={false}`. The Antd default is `true` and "
        "the entire wizard relies on it to keep operator-entered "
        "values across step navigation, SSL-mode branch swaps, and "
        "tcp/http frontend mode toggles."
    )
    assert "preserve: false" not in src, (
        "Bulgu #11 form-state pin: no Form / Form.Item in the "
        "wizard may pass `preserve: false` via spread props either."
    )


def test_phase_k_phase_d_resume_marks_cluster_synced_on_eager_swap():
    """Phase K Phase D (Bulgu #7 corner case) — when the resume
    effect successfully calls `selectCluster(draftCluster)` on its
    eager-swap path (ClusterContext was already loaded at mount),
    it MUST also call `setResumeClusterSynced(true)`.

    Without this, the header-sync deferred swap branch (which
    exists for the cold-mount race) would later misfire when the
    operator MANUALLY changes the header cluster post-resume —
    `resumedFromDraft && !resumeClusterSynced` would still be
    true, so the swap branch would snap the header back to the
    draft cluster.
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    # Locate the resume effect's eager-swap block.
    swap_anchor = "selectCluster(draftCluster);"
    swap_pos = src.find(swap_anchor)
    assert swap_pos >= 0, (
        "Phase K Phase D (Bulgu #7 corner case) regression: the "
        "resume effect's eager `selectCluster(draftCluster)` call "
        "is missing entirely. ClusterContext-loaded resumes will "
        "stop syncing the header at mount."
    )
    # The `setResumeClusterSynced(true)` marker must appear within
    # a small window AFTER the eager swap (in the same try block).
    window = src[swap_pos: swap_pos + 800]
    assert "setResumeClusterSynced(true);" in window, (
        "Phase K Phase D (Bulgu #7 corner case) regression: the "
        "resume effect no longer marks `resumeClusterSynced=true` "
        "after its eager swap. Operators changing the header AFTER "
        "a successful resume will be silently snapped back to the "
        "draft cluster by the header-sync deferred swap branch."
    )


def test_phase_k_phase_d_cluster_change_invalidates_dry_run():
    """Phase K Phase D (Bulgu #8) — mid-wizard cluster changes go
    through `form.setFieldsValue` (header sync), which is a
    SILENT Antd update — `onValuesChange` does NOT fire. The
    onValuesChange-driven dry-run invalidation cannot catch this
    case. The cluster-transition cleanup effect must therefore
    additionally reset `dryRunResult` to idle and bump
    `dryRunInvalidationTick` so a stale "clean" card from the
    PREVIOUS cluster does not linger on Step 4.

    Pin:
      * The cluster-transition cleanup body references
        `dryRunStatusRef.current` and `setDryRunInvalidationTick`
        (the tick bump that forces a re-fetch).
    """
    path = _REPO / "frontend" / "src" / "components" / "SiteWizard.js"
    src = _read_or_skip(path)
    # Look for the dry-run reset block INSIDE the cluster-transition
    # cleanup effect.
    anchor = "// Phase K Phase D (Bulgu #8):"
    block_start = src.find(anchor)
    assert block_start >= 0, (
        "Phase K Phase D (Bulgu #8) regression: the documented "
        "dry-run invalidation block inside the cluster-transition "
        "cleanup effect is missing. Mid-wizard cluster changes "
        "will now leave stale validation cards."
    )
    block_end = src.find("prevClusterRef.current = watchedClusterId;", block_start)
    assert block_end > block_start, (
        "Phase K Phase D (Bulgu #8) regression: cleanup effect "
        "structure changed; cannot locate the prevClusterRef "
        "write that should follow the dry-run reset."
    )
    block = src[block_start:block_end]
    assert "dryRunStatusRef.current" in block, (
        "Phase K Phase D (Bulgu #8) regression: cluster-transition "
        "cleanup no longer reads `dryRunStatusRef.current` to "
        "decide whether to bust the dry-run cache."
    )
    assert "setDryRunInvalidationTick" in block, (
        "Phase K Phase D (Bulgu #8) regression: cluster-transition "
        "cleanup no longer bumps `dryRunInvalidationTick`. The "
        "dry-run effect dep list will not detect the cluster "
        "change and Step 4 will display a stale clean card."
    )
    assert "setDryRunResult" in block, (
        "Phase K Phase D (Bulgu #8) regression: cluster-transition "
        "cleanup no longer resets `dryRunResult` to idle. The UI "
        "will display the previous cluster's status text until "
        "the next manual re-fetch."
    )
