import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  Card, Steps, Form, Input, Select, Button, Space, Alert, Modal,
  message, Row, Col, Tag, Tooltip, Switch, InputNumber, Divider, Spin,
  Collapse,
} from 'antd';
import {
  PlusOutlined, MinusCircleOutlined, ReloadOutlined,
  SaveOutlined, CheckCircleOutlined, ExclamationCircleOutlined,
  CloseCircleOutlined, SettingOutlined, LockOutlined,
  FilterOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

import { antdDomainsListRule } from '../utils/validation';
import { extractApiError } from '../utils/apiError';
import ACLRuleBuilder from './ACLRuleBuilder';
import { useCluster } from '../contexts/ClusterContext';

const { Option } = Select;

const SSL_MODES = [
  { value: 'acme', label: "Let's Encrypt (ACME)", description: 'Issue + auto-renew via Let\'s Encrypt' },
  { value: 'upload', label: 'Upload PEM cert', description: 'Provide certificate + private key now' },
  { value: 'existing', label: 'Reuse existing cert', description: 'Pick a cert already imported by an admin' },
  { value: 'none', label: 'HTTP only', description: 'Skip HTTPS entirely' },
];

const checkStatusToTag = (status) => {
  if (status === 'ok') return <Tag color="success" icon={<CheckCircleOutlined />}>OK</Tag>;
  if (status === 'warn') return <Tag color="warning" icon={<ExclamationCircleOutlined />}>WARN</Tag>;
  if (status === 'fail') return <Tag color="error" icon={<CloseCircleOutlined />}>FAIL</Tag>;
  if (status === 'skipped') return <Tag>SKIPPED</Tag>;
  return <Tag>{(status || '').toUpperCase()}</Tag>;
};

// R16 #v3: extractApiError lives in ../utils/apiError so SiteDrafts
// and any future wizard-adjacent component can reuse the same envelope-aware
// error parsing. See that file for the full shape rationale.

// R18c round 7 (Bulgu 2): when an operator resumes a saved draft, jump
// straight to the last step (Review & Apply) so they can submit without
// clicking Next four times. Defined as a module-level constant so future
// refactors that add/remove a step only need to update this single value.
// stepContents.length - 1 would also work but stepContents is recreated
// every render and adding it as an effect dependency conflicts with the
// mount-only intent of the draft hydrate effect.
const WIZARD_LAST_STEP = 4;
// Step indices: 0=Cluster & Domains, 1=Backend & Servers, 2=Frontend,
// 3=SSL & ACME, 4=Review & Apply. Named constant so the orphan-clear
// rescue navigation (Bulgu #14) does not hard-code the magic number.
const SSL_STEP_INDEX = 3;

// Phase K Phase C: map a Pydantic validation loc[] (e.g. ['body',
// 'frontend', 'name']) and a HAProxy directive prefix (e.g. 'bind',
// 'backend', 'use_backend') back to the wizard step that owns the
// field. The validation card uses this to render `Edit Step N`
// jump-back buttons next to each error.
const PYDANTIC_LOC_TO_STEP = {
  cluster_id: 0,
  domains: 0,
  backend: 1,
  servers: 1,
  frontend: 2,
  ssl: 3,
  apply_immediately: 4,
};
// Order matters — longer / more-specific prefixes first.
const HAPROXY_DIRECTIVE_TO_STEP = [
  ['http-request', 2],
  ['http-response', 2],
  ['use_backend', 2],
  ['redirect', 2],
  ['frontend', 2],
  ['acl', 2],
  ['bind ssl', 3],
  ['bind', 2],
  ['hsts', 3],
  ['ssl-min-ver', 3],
  ['ssl-max-ver', 3],
  ['ssl', 3],
  ['server', 1],
  ['backend', 1],
];

// Phase K Phase C audit-fix #2: Pydantic v2 raises model-level
// `model_validator(mode="after")` errors with `loc=()` (empty
// tuple) — FastAPI then prepends `'body'` so the operator-visible
// envelope is `loc=['body']` (length=1). The most operator-
// relevant case is PEM-stripped resume:
//   `enforce_acme_apply_and_http` raises "ssl.mode='upload'
//   requires a non-empty PEM-encoded certificate_content (if you
//   resumed a draft, PEM fields were stripped at save time …)"
// → loc=['body'], msg starts with "Value error, ssl.mode='upload'
// requires …". Without a content-aware fallback the validation
// card renders the message but no Edit-Step jumpback. Plan
// (lines 148, 234) explicitly requires Step-3 jumpback in this
// flow.
//
// Heuristic: when `loc` does not pinpoint a step on its own,
// scan the message text for the field/concept that the error
// references and route to the wizard step that owns it.
//
// Patterns are ordered MOST-ACTIONABLE first — i.e. the step the
// operator actually has to edit to resolve the error, not the
// step that "feels related". `enforce_acme_apply_and_http`
// raises cross-field messages like "ssl.mode='acme' requires
// apply_immediately=true" or "ssl.mode='acme' requires
// frontend.mode='http'". The operator must edit the FIELD ON
// THE RIGHT SIDE of the requirement, not the SSL mode that
// triggered it. Pattern order therefore goes:
//
//   1. apply_immediately       → Step 4 (Review)
//   2. wildcard / domains      → Step 0 (Cluster + Domains)
//   3. frontend.* / bind_port  → Step 2 (Frontend)
//   4. backend.* / server.*    → Step 1 (Backend)
//   5. PEM / ssl.* / hsts_*    → Step 3 (SSL/TLS) — general SSL fallback
//
// SSL is the catch-all LAST entry; this prevents a cross-field
// message that mentions "ssl.mode='acme'" but actually requires
// editing the FE bind_port from being mis-routed to Step 3.
//
// Pin: backend/tests/test_frontend_auth_bootstrap_phase_j.py::
// test_phase_k_sitewizard_pydantic_jumpback_falls_back_to_msg_for_root_errors
// + test_phase_k_sitewizard_pydantic_pattern_order_routes_acme_xfield_correctly
const PYDANTIC_MSG_TO_STEP_PATTERNS = [
  // Review step (4) — `apply_immediately` is the only review-step
  // field; matched first so "ssl.mode='acme' requires
  // apply_immediately=true" routes to Step 4 (where the operator
  // toggles the switch), not Step 3.
  [/\bapply_immediately\b/i, 4],
  // Cluster + domains step (0) — `wildcard` is matched here (not
  // under SSL) because the wildcard ACME error is fixed by
  // editing the domain list (or switching ssl.mode away from
  // acme on Step 3 — Step 0 is the more direct path).
  [/\b(wildcard|cluster_id|domains?)\b/i, 0],
  // Frontend step (2) — must come BEFORE the catch-all SSL
  // pattern; otherwise "ssl.mode='acme' requires frontend.mode=
  // 'http'" matches the generic `ssl\.` first and routes to
  // Step 3 even though the operator must edit the FE mode.
  [/\b(frontend\.|bind_port|https_redirect|tcp)\b/i, 2],
  // Backend step (1) — backend / server identifiers.
  [/\b(backend\.|server\.|servers\[)/i, 1],
  // SSL step (3) — catch-all for SSL/TLS-only fields. Order
  // matters: anything that could legitimately route to Step 0,
  // 1, 2, or 4 has already been matched above.
  [/\b(ssl\.|certificate_content|private_key_content|chain_content|ssl_certificate_id|PEM|acme|hsts_|ciphers|alpn)/i, 3],
];

function _locPathToStep(loc, msg) {
  // First-class: pinpoint via the structured `loc` if present
  // (e.g. ['body', 'frontend', 'name'] → step 2). FastAPI
  // prepends 'body' to the Pydantic loc so loc[1] is the
  // top-level SiteCreate field.
  if (Array.isArray(loc) && loc.length >= 2) {
    const top = loc[1];
    if (Object.prototype.hasOwnProperty.call(PYDANTIC_LOC_TO_STEP, top)) {
      return PYDANTIC_LOC_TO_STEP[top];
    }
  }
  // Fallback: SiteCreate-level model_validator errors land with
  // `loc=['body']` (length 1) — Pydantic v2 keeps the failing
  // field out of the loc when the validator runs at the model
  // root. Walk the message text to recover the step.
  if (typeof msg === 'string' && msg) {
    for (const [pattern, target] of PYDANTIC_MSG_TO_STEP_PATTERNS) {
      if (pattern.test(msg)) return target;
    }
  }
  return null;
}

function _directiveToStep(directive) {
  if (!directive || typeof directive !== 'string') return null;
  const lower = directive.toLowerCase().trim();
  for (const [prefix, target] of HAPROXY_DIRECTIVE_TO_STEP) {
    if (lower.startsWith(prefix)) return target;
  }
  return null;
}

// R18c round 9: sessionStorage key migration. The user-facing brand was
// renamed "Proxied Host" → "Site" in R18; the component file names
// (ProxiedHostWizard / ProxiedHostDrafts) were left behind by oversight
// and are now SiteWizard / SiteDrafts. The sessionStorage key follows
// the same rename to stay consistent. We READ from BOTH the new and
// the legacy key for one release window so an operator who saved a
// draft in a tab still running pre-rename code keeps it on resume.
const WIZARD_DRAFT_SESSION_KEY = 'site_wizard_draft';
const LEGACY_WIZARD_DRAFT_SESSION_KEY = 'proxied_host_wizard_draft';

const SiteWizard = () => {
  const navigate = useNavigate();
  // Phase K Phase D (Bulgu #1): consume the SAME header cluster
  // context that every other entity page (FrontendManagement,
  // BackendServers, SSLManagement, ACMEAutomation, …) reads from.
  // Pre-fix the wizard's Step 0 had its own cluster Select that was
  // entirely decoupled from the header — operators could (and did)
  // pick cluster A in the header, start the wizard, then choose
  // cluster B on Step 0 with NO visual indication that the wizard
  // would target a different cluster than every other tool. The
  // header is now the single source of truth: form.cluster_id is
  // sync'd from selectedCluster automatically, Step 0 shows a
  // read-only display, and Resume from a different cluster swaps
  // the header to the draft's cluster so post-resume edits stay
  // cluster-consistent.
  const { selectedCluster, clusters: clustersFromContext, selectCluster } = useCluster();
  const [step, setStep] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  // Phase K Phase D (Bulgu #1): the legacy `clusters` local state
  // was set by `fetchInitial` and consumed by Step 0's Select. With
  // Step 0 now reading from useCluster() (the same context every
  // other page uses), the local state is redundant — we keep
  // `clustersFromContext` (also exposed via useCluster) for the
  // Resume flow's draft.cluster_id → header sync. The duplicate
  // /api/clusters call from fetchInitial is removed below.
  const [existingCerts, setExistingCerts] = useState([]);
  // R18c round 10 (M2): track the cluster-scoped existing-cert fetch
  // state so the Submit button can be disabled while a resumed draft
  // is still reconciling its `ssl.ssl_certificate_id` against the
  // freshly-loaded list. Pre-round-10 the Resume flow jumped directly
  // to Review & Apply; if the cert had been deleted in the
  // background, the orphan-cleanup useEffect cleared the field
  // asynchronously *after* the user had already seen the populated
  // payload, and a fast Submit click could race the cleanup and
  // submit a stale id (→ FK 400). With this flag the Submit button
  // (and its keyboard equivalent) reflects "still resolving" state
  // until the fetch terminates and the cleanup pass runs.
  const [existingCertsLoading, setExistingCertsLoading] = useState(false);

  const [form] = Form.useForm();
  const [preflightResults, setPreflightResults] = useState(null);
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [previewResults, setPreviewResults] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [continueAnyway, setContinueAnyway] = useState(false);

  // v1.5.0 (Issue #14 R12): Let's Encrypt accounts populate Account selection
  // when an admin manages multiple LE accounts (e.g. staging + prod).
  const [acmeAccounts, setAcmeAccounts] = useState([]);

  // Default form values — v1.5.0 R12: more comprehensive defaults aligned with
  // HAProxy 2.4+ best practices (timeouts, ssl-min-ver TLSv1.2, ALPN h2).
  const initialValues = {
    domains: [],
    backend: {
      name: '',
      balance_method: 'roundrobin',
      mode: 'http',
      health_check_uri: '/',
      health_check_interval: 2000,
      health_check_expected_status: 200,
      timeout_connect: 10000,
      timeout_server: 60000,
      timeout_queue: 60000,
    },
    servers: [{
      server_name: 'srv1',
      server_address: '',
      server_port: 8080,
      weight: 100,
      check_enabled: true,
      ssl_enabled: false,
    }],
    frontend: {
      name: '',
      mode: 'http',
      bind_address: '*',
      bind_port: 80,
      https_redirect: false,
      compression: false,
      log_separate: false,
    },
    ssl: {
      mode: 'none',
      auto_renew: true,
      https_bind_port: 443,
      https_frontend_name_suffix: '-https',
      ssl_alpn: 'h2,http/1.1',
      ssl_min_ver: 'TLSv1.2',
      hsts_enabled: false,
      hsts_max_age: 31536000,
      hsts_include_subdomains: true,
      hsts_preload: false,
      ssl_strict_sni: false,
    },
    apply_immediately: false,
  };

  const [resumedFromDraft, setResumedFromDraft] = useState(false);
  // Phase K Phase D follow-up (Bulgu #14) — list of human-readable
  // orphan descriptions ("HTTPS frontend: cert #15", "server #1:
  // ca-file cert #13") surfaced inline on the SSL & ACME step
  // after the orphan-clear effect fires. Cleared once the operator
  // picks a replacement / switches mode (handled by SSL mode
  // onChange below). One-toast lifecycle is still owned by
  // `orphanWarnedRef`; this is the *persistent* in-page banner so
  // operators who dismiss the toast still see the explanation.
  const [orphanClearedCerts, setOrphanClearedCerts] = useState([]);
  const [pemStrippedOnResume, setPemStrippedOnResume] = useState(false);

  // Phase F (ACL UX parity with FrontendManagement): visual ACL Rule
  // Builder embedded in the Frontend step. The builder is the SAME
  // component used by the standalone FrontendManagement page so the
  // operator gets identical drag-list-based UX (match-type dropdowns,
  // backend pickers, redirect URL helpers) instead of a free-text
  // HAProxy directive textarea.
  //
  // We keep the ACL state OUT of the antd Form (the builder is a
  // controlled component with its own callback shape) and merge the
  // three rule arrays back into the wizard payload at submit time.
  // The `aclBuilderKey` lets us force a remount when the operator
  // resumes a draft so the builder hydrates the saved rules correctly
  // (otherwise the controlled-component cache from the previous
  // render keeps the empty arrays).
  const [aclBuilderData, setAclBuilderData] = useState({
    aclRules: [],
    useBackendRules: [],
    redirectRules: [],
  });
  const [aclBuilderKey, setAclBuilderKey] = useState(0);

  // Phase K Phase C: HAProxy dry-run validation state.
  //
  // Status state machine (mirrors the validation card the wizard
  // renders on Step 4):
  //   idle           — mounted, will auto-fire on Step 4 entry
  //   loading        — in flight (Spin)
  //   clean          — is_valid: true, no warnings (green)
  //   warnings_only  — is_valid: true, warnings.length > 0 (yellow)
  //   errors         — is_valid: false (red, blocks Create)
  //   pydantic_error — HTTP 422 from /preview (red, blocks Create)
  //   unavailable    — is_valid: null OR 5xx / 429 / network (orange,
  //                    Create stays enabled — mirrors create_site's
  //                    validator-crash-is-non-fatal posture)
  const [dryRunResult, setDryRunResult] = useState({
    status: 'idle',
    errors: [],
    warnings: [],
    infos: [],
    pydanticErrors: [],
    message: '',
  });
  // AbortController ref so a rapid Step 4 → Step 2 → Step 4 navigation
  // cancels the in-flight request instead of stacking.
  const dryRunAbortRef = useRef(null);
  // Phase K Phase C audit-fix #3: critical race-condition fix for the
  // "Validating against HAProxy…" stuck state.
  //
  // The original dry-run effect had `dryRunResult.status` in its deps
  // array AND called `setDryRunResult({status: 'loading'})` at the top
  // of its body. That meant:
  //   1. step=4 entry, status='idle' → effect body runs, fires fetch,
  //      registers a cleanup `() => controller.abort()`.
  //   2. setStatus('loading') commits → re-render → effect re-runs
  //      because status changed (idle → loading).
  //   3. Cleanup from step 1 fires BEFORE the new body: it aborts the
  //      controller — i.e. the in-flight fetch we just started!
  //   4. New body sees `status !== 'idle'` and returns early without
  //      registering a new fetch.
  //   5. The aborted fetch's `.catch` checks `signal.aborted` and
  //      returns without setting state. Status remains 'loading'
  //      forever. The card sits on "Validating against HAProxy…".
  //
  // Audit-fix #1 (round 1) only addressed the leave-Step-4 cleanup
  // branch; the enter-Step-4 self-abort was a separate failure mode
  // that surfaced as soon as a user actually drove the wizard end-
  // to-end on a real backend.
  //
  // The fix has three pieces:
  //   * `dryRunStatusRef` shadows the current status so the main
  //     effect can guard "already in flight / completed" reads
  //     WITHOUT putting `dryRunResult.status` in the dep array.
  //   * `dryRunInvalidationTick` is an explicit re-trigger
  //     counter; anywhere a caller wants to invalidate the cached
  //     result AND re-fire the dry-run, it bumps the tick. The
  //     onValuesChange handler does this when the operator edits a
  //     Step-4-visible field (e.g. the Apply Immediately switch).
  //   * The main effect's deps shrink to `[step, aclBuilderData,
  //     dryRunInvalidationTick]` — none of these change on a self-
  //     issued setDryRunResult, so the cleanup-aborts-its-own-
  //     fetch race is structurally impossible.
  const dryRunStatusRef = useRef('idle');
  useEffect(() => {
    dryRunStatusRef.current = dryRunResult.status;
  }, [dryRunResult.status]);
  const [dryRunInvalidationTick, setDryRunInvalidationTick] = useState(0);
  // Cluster-scoped existing backends so the operator can route ACL
  // matches to backends OTHER than the wizard's brand-new one (e.g.
  // route /api/* to an existing api-backend the team already runs).
  // Pre-populated when cluster_id changes and surfaced in the
  // ACLRuleBuilder backend dropdown alongside the wizard's new
  // backend name (virtual entry).
  const [clusterBackends, setClusterBackends] = useState([]);

  // R15 hotfix: Form.useWatch MUST be hoisted ABOVE the stepContents array
  // literal. Previously these lived after stepContents at the bottom of the
  // component, but stepContents references `sslMode` inline (e.g. the SSL
  // step's ACME info banner) — that's a `const` referenced before its
  // declaration in the same render scope. Webpack's production minifier
  // renames sslMode to a single letter ("N") and a strict-mode TDZ access
  // crashes the entire wizard with:
  //   ReferenceError: Cannot access 'N' before initialization
  // Dev mode tolerates this because variable hoisting / scope handling
  // is looser before minification — production users hit a white page.
  // Fix: declare these reactive watchers at the top of the component, so
  // every downstream JSX expression sees them already initialised.
  const sslMode = Form.useWatch(['ssl', 'mode'], form);
  // Phase K Phase D (Bulgu #6): `acmeBlocksDraft` was the gate for
  // the now-removed "Create as PENDING" button. With a single
  // submit button driven by `effectiveApply = sslMode === 'acme'`
  // (see handleSubmit) the gate is no longer needed — ACME's
  // apply_immediately=true is enforced by handleSubmit itself.

  // Phase F: Form.useWatch hooks for the ACL UX so the builder can
  // surface the wizard's brand-new backend (`backend.name`, still
  // being typed) alongside cluster-scoped existing backends. The
  // `cluster_id` watch is declared further down (it pre-existed for
  // SSL refresh) and re-used by the ACL backend-fetch effect below.
  const watchedBackendName = Form.useWatch(['backend', 'name'], form);
  const watchedFrontendMode = Form.useWatch(['frontend', 'mode'], form);
  const watchedHttpsRedirect = Form.useWatch(['frontend', 'https_redirect'], form);

  // Composite list passed to the ACL builder: cluster-scoped existing
  // backends PLUS a synthetic entry for the wizard's new backend
  // (only when the user has typed a name). Filter out the synthetic
  // entry if it collides with an existing backend so dropdowns stay
  // clean. Memoised so the builder doesn't see a fresh array on
  // every keystroke.
  const aclBuilderBackends = useMemo(() => {
    const existing = Array.isArray(clusterBackends) ? clusterBackends : [];
    const newName = (watchedBackendName || '').trim();
    if (!newName) return existing;
    const collision = existing.some((b) => b && b.name === newName);
    if (collision) return existing;
    // Match the shape FrontendManagement passes: { id, name, mode }.
    // The builder only reads `name`, but matching the shape avoids
    // surprise undefined-access regressions if the builder evolves.
    const synthetic = { id: `wizard-new-${newName}`, name: newName, mode: 'http', _isWizardNew: true };
    return [synthetic, ...existing];
  }, [clusterBackends, watchedBackendName]);

  const fetchInitial = useCallback(async () => {
    // R18c round 10 (M5): pre-round-10 a silent `catch { }` hid every
    // failure mode here (network outage, 500/503 from cluster manager,
    // 401/403 from a stale token) and the wizard rendered with empty
    // cluster + ACME account lists. Operators interpreted the empty
    // dropdowns as "RBAC says I have no clusters" and filed false
    // permission tickets. Promise.allSettled never throws, so the outer
    // try/catch only ever caught synchronous bugs — replaced with
    // explicit per-call surfacing of the rejection reason via
    // extractApiError + a single message.warning that is dismissable
    // and does NOT block the wizard (it stays usable for ACME-account
    // independent flows like "ssl.mode=upload"). Errors are emitted
    // separately so a partial outage shows exactly what is broken.
    // Phase K Phase D (Bulgu #1): /api/clusters is owned by
    // ClusterContext and shared across every page — duplicating
    // the fetch here would double the load on cluster-manager AND
    // race the context's hydration. Only fetch ACME accounts,
    // which the wizard exclusively uses.
    const [acmeRes] = await Promise.allSettled([
      axios.get('/api/letsencrypt/accounts'),
    ]);
    if (acmeRes.status === 'fulfilled') {
      const accounts = Array.isArray(acmeRes.value.data)
        ? acmeRes.value.data
        : (acmeRes.value.data?.accounts || []);
      setAcmeAccounts(accounts.filter((a) => a.status === 'valid' || !a.status));
    } else {
      // ACME accounts are optional for non-ACME wizard runs; downgrade
      // to an info-level toast so it is informational rather than
      // alarming when ssl.mode is 'upload' / 'existing' / 'none'.
      message.info(extractApiError(acmeRes.reason, "Could not load Let's Encrypt accounts"));
    }
  }, []);

  useEffect(() => { fetchInitial(); }, [fetchInitial]);

  // R18 fix: the existing-certificate list is cluster-scoped.
  //
  // Pre-R18 the wizard called `axios.get('/api/ssl')` which does not exist
  // (correct endpoint is `/api/ssl/certificates`). Result: every "Reuse
  // existing cert" attempt rendered an empty Select with "No data" — even
  // though the cluster had cluster-specific AND global certs imported.
  //
  // The list ALSO needs to refetch whenever the user changes the cluster
  // on Step 0: a cert that's global OR scoped to cluster A must not show
  // up while the wizard is targeting cluster B. We watch ['cluster_id']
  // and refetch on every change. The list remains empty until a cluster
  // is picked (matches the manual SSL Management UX).
  const watchedClusterId = Form.useWatch('cluster_id', form);
  // Phase K Phase D (Bulgu #1): keep form.cluster_id locked to the
  // header's selectedCluster. Two-way considerations:
  //   * Initial mount: form.cluster_id is 0 (default). If header
  //     already has a cluster, push it into the form so Step 0
  //     renders with the right value AND watchedClusterId-keyed
  //     fetches (existing certs, cluster backends) fire on the
  //     correct cluster from the first render.
  //   * Header changes mid-wizard: re-sync form.cluster_id so the
  //     fetches refresh and the cluster-transition cleanup effect
  //     wipes stale per-cluster cert ids. Pre-fix this was a hidden
  //     trap — header showed cluster B but Step 0 still showed
  //     cluster A and Submit went to cluster A.
  // Pin: prevClusterRef in the cluster-transition cleanup effect
  // below detects the mismatch and clears orphaned ssl_certificate_id
  // selections without spurious warnings.
  //
  // Phase K Phase D (Bulgu #7) — Resume cluster swap race fix.
  //
  // On a COLD mount (browser refresh of /sites/new after a Resume
  // click populated sessionStorage), ClusterContext is still loading
  // when the resume effect fires. `selectCluster(draftCluster)` is
  // skipped because `clustersFromContext=[]`. Then ClusterContext
  // finishes loading and `selectedCluster` becomes `defaultCluster`
  // (NOT the draft cluster) — and the naive header sync below would
  // overwrite the draft's `form.cluster_id` with the default cluster.
  // The cluster-transition cleanup effect then misreads that
  // overwrite as a user-driven switch and wipes the draft's cert
  // selections (the Bulgu #5 second-order failure).
  //
  // The fix: when we ARE in a post-resume state AND the draft's
  // cluster is now visible in `clustersFromContext`, push the
  // header TO the draft cluster (one-shot) instead of forcing the
  // form to follow the header. `resumeClusterSynced` gates the
  // swap to exactly one attempt so a later operator-driven header
  // cluster change is honoured normally.
  const selectClusterRef = useRef(selectCluster);
  useEffect(() => {
    selectClusterRef.current = selectCluster;
  }, [selectCluster]);
  const [resumeClusterSynced, setResumeClusterSynced] = useState(false);
  useEffect(() => {
    if (!selectedCluster) return;
    const cur = form.getFieldValue('cluster_id');
    if (cur === selectedCluster.id) return;
    if (
      resumedFromDraft &&
      !resumeClusterSynced &&
      cur &&
      Array.isArray(clustersFromContext) &&
      clustersFromContext.length > 0
    ) {
      const draftCluster = clustersFromContext.find((c) => c.id === cur);
      if (draftCluster) {
        try { selectClusterRef.current(draftCluster); } catch (_) { /* noop */ }
        setResumeClusterSynced(true);
        return;
      }
    }
    form.setFieldsValue({ cluster_id: selectedCluster.id });
    if (!resumeClusterSynced) setResumeClusterSynced(true);
    // selectCluster is read via ref to keep the dep set small and
    // avoid spurious re-runs on every ClusterProvider render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCluster, form, resumedFromDraft, resumeClusterSynced, clustersFromContext]);
  // R18 audit fix: track the previous cluster so we can clear stale
  // cert selections (`ssl.ssl_certificate_id` and per-server
  // `ssl_certificate_id`) when the user switches clusters mid-wizard.
  // Without this, a cert id valid for cluster A would still sit in the
  // form when switching to cluster B and either confuse the user (the
  // dropdown would show "(invalid)") or land in the submit payload and
  // get rejected at the backend with a generic 400. We use a ref to
  // detect the *transition*; the very first hydration must not clear.
  const prevClusterRef = React.useRef(undefined);
  useEffect(() => {
    if (
      prevClusterRef.current !== undefined &&
      prevClusterRef.current !== watchedClusterId
    ) {
      try {
        const cur = form.getFieldsValue(true);
        const updates = {};
        if (cur?.ssl?.ssl_certificate_id) {
          updates.ssl = { ...(cur.ssl || {}), ssl_certificate_id: undefined };
        }
        if (Array.isArray(cur?.servers)) {
          updates.servers = cur.servers.map((s) =>
            s && s.ssl_certificate_id ? { ...s, ssl_certificate_id: undefined } : s,
          );
        }
        if (Object.keys(updates).length) {
          form.setFieldsValue(updates);
        }
      } catch (_e) { /* noop — best-effort cleanup */ }
      // Phase K Phase D (Bulgu #8): mid-wizard cluster change must
      // invalidate any cached dry-run result. The validation
      // applies to the OLD cluster's HAProxy synthesis; after the
      // switch the operator's wizard payload targets a different
      // cluster's config so a "clean" card lingering from the
      // previous cluster would mislead. The cluster change goes
      // through `form.setFieldsValue` (header sync) which is a
      // SILENT Antd update (does NOT fire `onValuesChange`), so
      // the onValuesChange invalidation path below cannot catch
      // it. Force the reset + tick bump here so the dry-run
      // effect re-fires against the new cluster the next time the
      // operator is on Step 4.
      if (dryRunStatusRef.current !== 'idle') {
        setDryRunResult({
          status: 'idle',
          errors: [],
          warnings: [],
          infos: [],
          pydanticErrors: [],
          message: '',
        });
        setDryRunInvalidationTick((t) => t + 1);
      }
    }
    prevClusterRef.current = watchedClusterId;
  }, [watchedClusterId, form]);
  useEffect(() => {
    if (!watchedClusterId) {
      setExistingCerts([]);
      setExistingCertsLoading(false);
      return;
    }
    let cancelled = false;
    setExistingCertsLoading(true);
    (async () => {
      try {
        // No usage_type filter — the wizard surfaces existing certs for
        // BOTH HTTPS frontend ('frontend' usage) and server-side mTLS
        // ('client' / generic) selectors. Filtering server-side would
        // hide perfectly valid choices.
        const res = await axios.get(
          `/api/ssl/certificates?cluster_id=${encodeURIComponent(watchedClusterId)}`,
        );
        if (cancelled) return;
        const data = res.data;
        const certs = Array.isArray(data) ? data : (data?.certificates || []);
        // Surface the most relevant fields for the dropdown — `name` is
        // the operator-given label, `domain` (= primary_domain) gives
        // visual context. `is_active=false` certs are already filtered
        // server-side; we still defensively keep only active rows.
        setExistingCerts(
          certs
            .filter((c) => c && (c.is_active !== false))
            .map((c) => ({
              id: c.id,
              name: c.name,
              primary_domain: c.primary_domain || c.domain || '',
              ssl_type: c.ssl_type,
              usage_type: c.usage_type,
            })),
        );
      } catch (err) {
        if (cancelled) return;
        // R18 audit fix (round 4 #G): pre-R18 every error fell into
        // the same "set empty" branch — including 401 from the now-
        // protected /api/ssl/certificates endpoint. That made an
        // expired session look like "no certs imported" instead of a
        // login prompt. Surface auth failures explicitly so the
        // operator knows to re-authenticate; for any other error we
        // still degrade gracefully to an empty Select (the wizard
        // works in upload/acme/none modes regardless).
        const status = err?.response?.status;
        setExistingCerts([]);
        if (status === 401) {
          try { message.error('Session expired — please sign in again to load certificates.'); } catch (_) { /* noop */ }
        }
      } finally {
        if (!cancelled) setExistingCertsLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [watchedClusterId]);

  // Phase F: cluster-scoped existing-backend fetch for the embedded
  // ACLRuleBuilder. The use_backend_rules dropdown needs the OTHER
  // backends in this cluster so the operator can route ACL matches
  // (e.g. /api/* → existing api-backend) without hand-typing a name
  // and risking a typo that would silently break HAProxy parsing.
  // Mirrors the same /api/backends?cluster_id=... call that
  // FrontendManagement uses, so wizard parity matches manual UX.
  useEffect(() => {
    if (!watchedClusterId) {
      setClusterBackends([]);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await axios.get('/api/backends', {
          params: { cluster_id: watchedClusterId },
          headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
          },
        });
        if (cancelled) return;
        const data = res.data;
        const list = Array.isArray(data) ? data : (data?.backends || []);
        setClusterBackends(list);
      } catch (err) {
        if (cancelled) return;
        // Soft-fail: if backend listing is unavailable the wizard
        // still works (the operator can route ACLs to the wizard's
        // brand-new backend; existing-backend routing is opt-in
        // sugar). Log to console so diagnosis is possible without
        // blocking the create flow.
        console.warn('Wizard: failed to fetch cluster backends for ACL builder:', err);
        setClusterBackends([]);
      }
    })();
    return () => { cancelled = true; };
  }, [watchedClusterId]);

  // R18b audit fix (round 3 #7): when a draft is resumed it can carry
  // an `ssl.ssl_certificate_id` (or per-server `ssl_certificate_id`)
  // pointing at a cert that has since been deleted via SSL Management.
  // Pre-fix the Select silently rendered the orphan id as an empty
  // option and the operator had no idea the cert was gone — submit
  // would then 400 at FK validation. We watch for that mismatch
  // whenever existingCerts refresh, surface a single warning toast,
  // and clear the dangling field so the operator picks a valid cert
  // (or switches mode). Cleared in one shot to avoid spamming toasts.
  const orphanWarnedRef = useRef(new Set());
  useEffect(() => {
    if (!watchedClusterId) return;
    // Phase K Phase C audit-fix #4 (Bulgu #5): the orphan-detect
    // pass must NOT run while the existingCerts fetch is in
    // flight. Pre-fix the effect ran on every render where
    // `watchedClusterId` had just changed (e.g. resume from draft
    // updating cluster_id=7 via form.setFieldsValue). At that
    // moment `existingCerts` is still the previous tick's empty
    // array — so `certIds = new Set()` and any form-resident
    // ssl_certificate_id looks like an orphan. The effect then
    // calls `form.setFieldsValue({ssl: {ssl_certificate_id:
    // undefined}})`, wiping the freshly-resumed selection.
    // Operator returns to Step 3 and sees an empty dropdown even
    // though the draft DID carry a valid cert id.
    //
    // The fix: short-circuit while the certs are still loading.
    // The effect will re-run when existingCerts changes from []
    // to the loaded list (deps include existingCerts), at which
    // point certIds reflects reality and the orphan check is
    // accurate.
    if (existingCertsLoading) return;
    // Bulgu #2 follow-up — usage_type compatibility is part of
    // "exists for THIS slot". The HTTPS frontend bind expects a
    // cert with `usage_type='frontend'` (matches BackendServers.js
    // and the SSL Management filter); the per-server `ca-file`
    // slot expects `usage_type='server'`. Pre-fix, a cert that an
    // admin re-tagged from 'frontend' → 'server' on the SSL
    // Management page would pass the orphan check (id is still in
    // the cluster list) but the dropdown filter below would hide
    // it from the operator. They'd see a populated form field
    // with no matching option — Pydantic would then reject at
    // submit ("ssl.mode='existing' requires ssl.ssl_certificate_id"
    // / "A CA bundle is required..."). Treat usage_type mismatch
    // as orphan so the form is auto-cleared and the operator is
    // prompted to pick a replacement on Step 3.
    const certById = new Map();
    for (const c of existingCerts) certById.set(c.id, c);
    const isCompatible = (certId, expectedUsage) => {
      const c = certById.get(certId);
      if (!c) return false;
      // Legacy rows without `usage_type` default to 'frontend' on
      // the backend (routers/ssl.py). Treat undefined === 'frontend'
      // so the operator's pre-usage_type SSL imports keep working.
      const ut = c.usage_type || 'frontend';
      return ut === expectedUsage;
    };
    const cur = form.getFieldsValue(true);
    const orphans = [];
    const updates = {};
    if (
      cur?.ssl?.ssl_certificate_id
      && !isCompatible(cur.ssl.ssl_certificate_id, 'frontend')
    ) {
      const detail = certById.has(cur.ssl.ssl_certificate_id)
        ? `wrong usage_type (expected 'frontend')`
        : `not found`;
      orphans.push(
        `HTTPS frontend: cert #${cur.ssl.ssl_certificate_id} (${detail})`,
      );
      updates.ssl = { ...(cur.ssl || {}), ssl_certificate_id: undefined };
    }
    if (Array.isArray(cur?.servers)) {
      const newServers = cur.servers.map((s, i) => {
        if (s && s.ssl_certificate_id && !isCompatible(s.ssl_certificate_id, 'server')) {
          const detail = certById.has(s.ssl_certificate_id)
            ? `wrong usage_type (expected 'server')`
            : `not found`;
          orphans.push(
            `server #${i + 1}: ca-file cert #${s.ssl_certificate_id} (${detail})`,
          );
          return { ...s, ssl_certificate_id: undefined };
        }
        return s;
      });
      if (newServers.some((s, i) => s !== cur.servers[i])) {
        updates.servers = newServers;
      }
    }
    if (orphans.length) {
      const key = orphans.sort().join('|');
      if (!orphanWarnedRef.current.has(key)) {
        orphanWarnedRef.current.add(key);
        try {
          message.warning({
            content: `Selected SSL certificate(s) no longer exist and were cleared: ${orphans.join(', ')}.`,
            duration: 6,
          });
        } catch (_) { /* noop */ }
      }
      // Bulgu #14 — persistent in-page banner. The toast above is
      // ephemeral and operators on a busy screen sometimes miss it
      // entirely. Surface the same diagnostic on Step 3 (SSL & ACME)
      // so the operator can act on it after they've navigated there.
      setOrphanClearedCerts(orphans.slice());
      // Phase K Phase D follow-up (Bulgu #14) — when the cleared cert
      // is the HTTPS frontend cert AND `ssl.mode === 'existing'`,
      // the form is left in a logically inconsistent state
      // (`mode=existing` requires `ssl_certificate_id`). The
      // Pydantic guard rejects that at submit and the wizard's
      // dry-run on Step 5 surfaces a hard validation error,
      // confusingly blaming the operator for state THEY did not
      // create (the orphan-cleanup did). Auto-degrade the mode
      // to 'none' so the form stays self-consistent and the
      // dry-run proceeds — the operator is then prompted via a
      // banner on Step 3 (SSL & ACME) to pick a replacement.
      if (
        updates.ssl
        && updates.ssl.ssl_certificate_id === undefined
        && (cur?.ssl?.mode === 'existing')
      ) {
        updates.ssl = { ...updates.ssl, mode: 'none' };
        try {
          message.warning({
            content:
              'SSL mode reverted to "none" because the previously '
              + 'selected certificate is no longer available. Re-open '
              + 'Step 4 (SSL & ACME) to pick a replacement or switch '
              + 'mode before creating the site.',
            duration: 8,
          });
        } catch (_) { /* noop */ }
      }
      try { form.setFieldsValue(updates); } catch (_) { /* noop */ }

      // Phase K Phase D follow-up (Bulgu #14) — if the orphan
      // clear happened while the operator was already parked at
      // Review & Apply (most-common path after a draft resume),
      // bounce them back to the SSL step so the cleared field
      // is visible and easy to fix. We do this exactly once per
      // distinct orphan set — same dedup key as the toast — so
      // a re-render of the same orphan state doesn't keep
      // hijacking the operator's navigation.
      if (step === WIZARD_LAST_STEP && resumedFromDraft) {
        try {
          // Defer the navigation to next tick so the form
          // setFieldsValue above flushes first; otherwise the
          // Step 3 render reads the pre-clear ssl.ssl_certificate_id
          // out of the form snapshot and the banner flashes.
          setTimeout(() => setStep(SSL_STEP_INDEX), 0);
        } catch (_) { /* noop */ }
      }
    }
  }, [existingCerts, existingCertsLoading, watchedClusterId, form, step, resumedFromDraft]);

  // R18c round 10 (M8): pre-round-10 the Review step had a render-time
  // setTimeout(...setFieldsValue, 0) hack to force apply_immediately=true
  // when ssl.mode=='acme'. That is a setState-during-render anti-pattern
  // — React 18 Strict Mode double-renders it, and rapid step navigation
  // can stack pending timeouts. Move the coercion to a proper useEffect
  // that watches sslMode (already a Form.useWatch above) so the form
  // field updates exactly once per mode transition, before the operator
  // sees the Review step.
  useEffect(() => {
    if (sslMode === 'acme') {
      const cur = form.getFieldValue('apply_immediately');
      if (cur !== true) {
        form.setFieldsValue({ apply_immediately: true });
      }
    }
  }, [sslMode, form]);

  // Phase K Phase B: when the operator switches the frontend to TCP
  // mode, force-clear `https_redirect`. The Pydantic
  // `reject_tcp_mode_with_https_redirect` validator (Phase A) refuses
  // this combination at submit time; clearing it eagerly keeps the
  // form in a submittable state without surprising the user. We only
  // clear the boolean flag — the Switch is also disabled below in
  // the JSX so the operator cannot re-enable it while `mode==='tcp'`.
  useEffect(() => {
    if (watchedFrontendMode === 'tcp' && watchedHttpsRedirect) {
      form.setFields([
        { name: ['frontend', 'https_redirect'], value: false },
      ]);
    }
  }, [watchedFrontendMode, watchedHttpsRedirect, form]);

  // Phase K Phase C: auto-fire the HAProxy dry-run validation when
  // the operator enters Step 4 (Review & Apply). The validation card
  // we render below switches from `idle` → `loading` → final state
  // based on the response severity. AbortController cancels the
  // in-flight request when the operator navigates away (rapid
  // Step 4 → Step 2 → Step 4 shouldn't stack requests).
  useEffect(() => {
    if (step !== WIZARD_LAST_STEP) {
      if (dryRunAbortRef.current) {
        try { dryRunAbortRef.current.abort(); } catch (_) { /* noop */ }
        dryRunAbortRef.current = null;
      }
      // Phase K Phase C audit-fix #1: when the operator navigates
      // AWAY from Step 4, also reset the cached dry-run result to
      // `idle`. Otherwise a stale `clean` / `errors` /
      // `warnings_only` status survives across the round-trip and
      // the auto-fire branch below (`if (statusRef !== 'idle') return
      // undefined;`) suppresses the next fetch when the operator
      // returns. The most common path that exposes this is Step 2 →
      // ACL edit → Step 4: the ACL builder lives OUTSIDE the antd
      // Form so its mutations do NOT trigger Form's onValuesChange
      // invalidation. Without this reset the operator sees
      // yesterday's validation result even after they added /
      // removed routing rules. Re-running on every Step 4 entry is
      // the explicit Phase C plan contract ("auto-fire dry-run on
      // Step 4 entry") and is rate-limit-safe because the entry
      // itself is operator-initiated (Next button click; no
      // programmatic loop).
      if (dryRunStatusRef.current !== 'idle') {
        setDryRunResult({
          status: 'idle',
          errors: [],
          warnings: [],
          infos: [],
          pydanticErrors: [],
          message: '',
        });
      }
      return undefined;
    }
    // Phase K Phase C audit-fix #3: read via REF so we don't need
    // `dryRunResult.status` in the dep array. The dep array
    // contains only externally-driven triggers (step change,
    // aclBuilderData change, tick bump from onValuesChange) so a
    // self-issued setDryRunResult({status: 'loading'}) below
    // cannot re-fire the effect and abort its own fetch.
    if (dryRunStatusRef.current !== 'idle') return undefined;

    const controller = new AbortController();
    dryRunAbortRef.current = controller;
    setDryRunResult({
      status: 'loading',
      errors: [],
      warnings: [],
      infos: [],
      pydanticErrors: [],
      message: '',
    });

    (async () => {
      try {
        const values = form.getFieldsValue(true);
        const valuesWithAcls = {
          ...values,
          frontend: {
            ...(values.frontend || {}),
            acl_rules: aclBuilderData.aclRules || [],
            use_backend_rules: aclBuilderData.useBackendRules || [],
            redirect_rules: aclBuilderData.redirectRules || [],
          },
        };
        const res = await axios.post(
          '/api/sites/preview',
          valuesWithAcls,
          {
            params: { validate_haproxy_config: true },
            signal: controller.signal,
          },
        );
        if (controller.signal.aborted) return;
        const v = res.data?.validation;
        if (!v) {
          setDryRunResult({
            status: 'unavailable',
            errors: [], warnings: [], infos: [], pydanticErrors: [],
            message: 'HAProxy validation unavailable in this response.',
          });
          return;
        }
        if (v.is_valid === null) {
          setDryRunResult({
            status: 'unavailable',
            errors: [], warnings: [], infos: [], pydanticErrors: [],
            message: v.validator_error || 'Validator infrastructure error.',
          });
        } else if (v.is_valid === false) {
          setDryRunResult({
            status: 'errors',
            errors: v.errors || [],
            warnings: v.warnings || [],
            infos: v.infos || [],
            pydanticErrors: [],
            message: '',
          });
        } else if ((v.warning_count || 0) > 0 || (v.warnings || []).length > 0) {
          setDryRunResult({
            status: 'warnings_only',
            errors: [],
            warnings: v.warnings || [],
            infos: v.infos || [],
            pydanticErrors: [],
            message: '',
          });
        } else {
          setDryRunResult({
            status: 'clean',
            errors: [],
            warnings: [],
            infos: v.infos || [],
            pydanticErrors: [],
            message: '',
          });
        }
      } catch (err) {
        if (
          controller.signal.aborted ||
          err?.name === 'CanceledError' ||
          err?.name === 'AbortError' ||
          err?.code === 'ERR_CANCELED'
        ) {
          return;
        }
        const status = err?.response?.status;
        if (status === 422 && Array.isArray(err.response?.data?.detail)) {
          setDryRunResult({
            status: 'pydantic_error',
            errors: [], warnings: [], infos: [], pydanticErrors: err.response.data.detail,
            message: '',
          });
        } else if (status === 429) {
          setDryRunResult({
            status: 'unavailable',
            errors: [], warnings: [], infos: [], pydanticErrors: [],
            message: "You're validating too quickly — wait a few seconds and try again.",
          });
        } else {
          setDryRunResult({
            status: 'unavailable',
            errors: [], warnings: [], infos: [], pydanticErrors: [],
            message: extractApiError(err, 'HAProxy validation could not be performed at this time.'),
          });
        }
      } finally {
        if (dryRunAbortRef.current === controller) {
          dryRunAbortRef.current = null;
        }
      }
    })();

    return () => {
      // Phase K Phase C audit-fix #3: only this effect's OWN
      // controller may be aborted on cleanup. We also clear the
      // ref ONLY if it still points to this controller so a fresh
      // fetch that overwrote the ref between effect runs is not
      // accidentally nulled.
      if (controller && !controller.signal.aborted) {
        try { controller.abort(); } catch (_) { /* noop */ }
      }
      if (dryRunAbortRef.current === controller) {
        dryRunAbortRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, form, aclBuilderData, dryRunInvalidationTick]);

  // Bulgu #5 fix: hydrate the form from a draft when SiteDrafts navigated
  // here with sessionStorage payload. Detect PEM-stripped fields so we can warn
  // the user that they were scrubbed at save time (M14/M9).
  //
  // R13 fix (Bulgu #v9): use a TWO-LEVEL deep merge instead of a flat
  // spread. A drafted payload from the v1.5.0 first deploy lacks the new
  // R12 advanced fields (ssl_alpn / ssl_min_ver / hsts_*, backend
  // timeout_*, etc.). With a flat spread `{...initialValues, ...parsed}`
  // the parsed.ssl object would replace initialValues.ssl WHOLESALE,
  // wiping the modern UI defaults the wizard pre-populates for new
  // hosts. Merge each top-level group dictionary so missing nested keys
  // fall back to initialValues.
  const _mergeGroup = (base, override) => {
    if (override == null) return base;
    if (typeof override !== 'object' || Array.isArray(override)) return override;
    return { ...(base || {}), ...override };
  };
  useEffect(() => {
    try {
      // R18c round 9: prefer the new key but fall back to the legacy
      // one so a draft saved by SiteDrafts (which writes both keys
      // during the migration window) still hydrates if the new key is
      // somehow missing (e.g. older browser tab cache).
      const raw =
        sessionStorage.getItem(WIZARD_DRAFT_SESSION_KEY) ||
        sessionStorage.getItem(LEGACY_WIZARD_DRAFT_SESSION_KEY);
      if (!raw) return;
      // R18c round 8 (Bulgu A): pre-fix the drafts page double-encoded the
      // payload (because backend returned a raw JSON string, JSON.stringify
      // re-quoted it). Resume then JSON.parsed back to a string — never
      // a dict — so hydrate silently bailed. Now defensively re-parse
      // until we hit a dict (or give up). This is forwards-compatible:
      // properly-encoded payloads from the new code path parse to a dict
      // on the FIRST attempt.
      let parsed = JSON.parse(raw);
      let attempts = 0;
      while (typeof parsed === 'string' && attempts < 3) {
        try {
          parsed = JSON.parse(parsed);
        } catch (_e) {
          break;
        }
        attempts += 1;
      }
      // Clear BOTH keys so nothing lingers across navigations.
      sessionStorage.removeItem(WIZARD_DRAFT_SESSION_KEY);
      sessionStorage.removeItem(LEGACY_WIZARD_DRAFT_SESSION_KEY);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        // Detect any blank PEM placeholders left by the backend's strip pass
        const ssl = parsed.ssl || {};
        const sslHasBlankPem =
          ssl.mode === 'upload' &&
          (ssl.certificate_content === '' || ssl.private_key_content === '');
        setPemStrippedOnResume(sslHasBlankPem);
        const merged = {
          ...initialValues,
          ...parsed,
          backend: _mergeGroup(initialValues.backend, parsed.backend),
          frontend: _mergeGroup(initialValues.frontend, parsed.frontend),
          ssl: _mergeGroup(initialValues.ssl, parsed.ssl),
          // servers is an array — keep the parsed list as-is (replace),
          // but if it's missing/empty fall back to initialValues.
          servers: Array.isArray(parsed.servers) && parsed.servers.length
            ? parsed.servers
            : initialValues.servers,
        };
        // Phase K Phase D (Bulgu #1): pin the cluster change-detection
        // ref BEFORE setFieldsValue so the cluster-transition cleanup
        // effect does NOT misread "draft hydration" as "user switched
        // clusters" and wipe the freshly-resumed ssl_certificate_id /
        // per-server CA bundle ids. Combined with the
        // `existingCertsLoading` short-circuit in the orphan-detect
        // effect, this guarantees a resumed draft retains every
        // operator-saved cert selection.
        if (merged.cluster_id !== undefined && merged.cluster_id !== null) {
          prevClusterRef.current = merged.cluster_id;
          // ALSO sync the header to the draft's cluster so post-
          // resume edits, Step 0 display, and per-cluster fetches
          // all converge on the draft's target cluster. If the
          // header already matches, this is a no-op (selectCluster
          // tolerates re-selecting the same cluster).
          try {
            if (
              Array.isArray(clustersFromContext) &&
              clustersFromContext.length > 0
            ) {
              const draftCluster = clustersFromContext.find(
                (c) => c.id === merged.cluster_id,
              );
              if (draftCluster) {
                if (
                  !selectedCluster ||
                  selectedCluster.id !== merged.cluster_id
                ) {
                  selectCluster(draftCluster);
                }
                // Phase K Phase D (Bulgu #7) — mark the post-resume
                // header swap as DONE so the deferred swap branch
                // in the header sync effect (which exists for the
                // cold-mount race where ClusterContext loads AFTER
                // this point) does NOT later revert a manual
                // operator-driven header change back to the draft
                // cluster. Without this, an operator changing the
                // header AFTER a successful eager swap here would
                // be silently snapped back to the draft cluster.
                setResumeClusterSynced(true);
              }
            }
          } catch (_e) { /* best-effort: cluster sync is sugar, not safety */ }
        }
        form.setFieldsValue(merged);
        // Phase F: hydrate the ACL builder from the saved draft if
        // the resumed payload carries any of the three rule arrays
        // (acl_rules / use_backend_rules / redirect_rules under
        // `frontend`). Force a builder remount via key bump so the
        // controlled component reflects the new initial arrays.
        const resumedFE = (parsed && parsed.frontend) || {};
        const aclState = {
          aclRules: Array.isArray(resumedFE.acl_rules) ? resumedFE.acl_rules : [],
          useBackendRules: Array.isArray(resumedFE.use_backend_rules) ? resumedFE.use_backend_rules : [],
          redirectRules: Array.isArray(resumedFE.redirect_rules) ? resumedFE.redirect_rules : [],
        };
        if (
          aclState.aclRules.length ||
          aclState.useBackendRules.length ||
          aclState.redirectRules.length
        ) {
          setAclBuilderData(aclState);
          setAclBuilderKey((k) => k + 1);
        }
        setResumedFromDraft(true);
        // R18c round 7 (Bulgu 2): jump to Review & Apply so the operator
        // sees the full populated payload immediately. They can still
        // click Previous to edit any earlier step's fields.
        setStep(WIZARD_LAST_STEP);
      }
    } catch (_e) {
      /* ignore — fall back to clean init */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchSuggestions = async () => {
    try {
      const values = form.getFieldsValue(true);
      if (!values.cluster_id || !values.domains || values.domains.length === 0) return;
      const res = await axios.get('/api/sites/suggest', {
        params: { cluster_id: values.cluster_id, domain: values.domains[0] },
      });
      const s = res.data || {};
      form.setFieldsValue({
        backend: { ...values.backend, name: values.backend?.name || s.backend_name },
        frontend: { ...values.frontend, name: values.frontend?.name || s.frontend_name },
      });
    } catch (_e) {
      /* noop */
    }
  };

  // ---------- Preflight (ACME) ----------
  const runPreflight = async () => {
    const values = form.getFieldsValue(true);
    if (!values.cluster_id || !values.domains || values.domains.length === 0) {
      message.error('Cluster and domains are required for preflight');
      return;
    }
    setPreflightLoading(true);
    setPreflightResults(null);
    // R18 audit fix (round 4 #F): clear the "Continue anyway" override
    // whenever a fresh preflight run is initiated. Pre-R18 the flag
    // was sticky — an operator could tick it once, click "Refresh
    // preflight" after fixing some-but-not-all issues, see new
    // failures, and STILL have the submit button bypass them. The
    // override must be re-affirmed for each set of results.
    setContinueAnyway(false);
    try {
      const res = await axios.post('/api/sites/preflight-acme', {
        cluster_id: values.cluster_id,
        domains: values.domains,
      });
      setPreflightResults(res.data);
    } catch (err) {
      // R16 #v3: envelope-aware
      message.error(extractApiError(err, 'Preflight failed'));
    } finally {
      setPreflightLoading(false);
    }
  };

  // ---------- Preview ----------
  const runPreview = async () => {
    setPreviewLoading(true);
    setPreviewResults(null);
    try {
      // Bug B fix: getFieldsValue(true) returns ALL registered fields,
      // including display:none ones, so the preview captures the full
      // wizard state regardless of which step is currently visible.
      const values = form.getFieldsValue(true);
      // Phase F: inject the ACL builder's three rule arrays into the
      // preview payload so the operator sees what HAProxy will
      // actually emit (acl / use_backend / redirect lines) before
      // committing.
      const valuesWithAcls = {
        ...values,
        frontend: {
          ...(values.frontend || {}),
          acl_rules: aclBuilderData.aclRules || [],
          use_backend_rules: aclBuilderData.useBackendRules || [],
          redirect_rules: aclBuilderData.redirectRules || [],
        },
      };
      const res = await axios.post('/api/sites/preview', valuesWithAcls);
      setPreviewResults(res.data);
    } catch (err) {
      // R16 #v3: use the envelope-aware extractor so users see the
      // ACTUAL server-side reason (validation field path, RBAC denial,
      // collision warning) instead of a generic "Preview failed".
      message.error(extractApiError(err, 'Preview failed'));
    } finally {
      setPreviewLoading(false);
    }
  };

  // ---------- Submit ----------
  // Phase K Phase D (Bulgu #6): the wizard used to expose TWO buttons
  // — `Create as PENDING` (apply_immediately=false) and `Create &
  // Apply` (apply_immediately=true). Operators (and the user during
  // R18c review) found that confusing: the standard manual flow on
  // FrontendManagement / BackendServers / SSLManagement always
  // produces a PENDING version that the operator then reviews on
  // Apply Management before pulling the trigger. Two wizard buttons
  // bypassed that convention and trained operators to "always
  // Create & Apply", defeating the change-review benefit of Apply
  // Management.
  //
  // Standard flow alignment: ONE submit button — "Create Site". Its
  // semantics are:
  //   * Default (none / upload / existing SSL modes): apply_immediately
  //     = false → backend returns `created_pending` → operator is
  //     navigated to /apply-management, where they can audit the
  //     bulk version and click Apply (same Agent-pull cadence as
  //     manual entity creation).
  //   * ACME SSL mode: apply_immediately = true (FORCED by backend's
  //     SiteCreate.enforce_acme_apply_and_http model_validator, M22).
  //     Operator is navigated to /frontends after the agent confirms
  //     the HTTP frontend that satisfies the HTTP-01 challenge.
  //
  // The signature still accepts an optional `applyImmediately` param
  // so the (deprecated) entry-points and the test pin tests don't
  // break — but the default is now mode-driven, not button-driven.
  const handleSubmit = async (applyImmediately) => {
    try {
      // Bug B fix: validateFields returns only mounted/touched fields. Now
      // that ALL step contents stay mounted, validateFields covers the
      // whole form. We additionally merge in getFieldsValue(true) as a
      // belt-and-braces defense against display:none + form.preserve
      // edge-cases.
      const validated = await form.validateFields();
      const all = form.getFieldsValue(true);
      const values = { ...all, ...validated };
      // Phase K Phase D: derive apply_immediately from the SSL mode
      // (ACME forces apply) when the caller did not explicitly pass
      // a value. Eliminates the "wrong button → wrong flow" UX.
      const sslModeAtSubmit = values.ssl?.mode;
      const effectiveApply =
        applyImmediately === undefined
          ? sslModeAtSubmit === 'acme'
          : !!applyImmediately;
      values.apply_immediately = effectiveApply;
      if (sslModeAtSubmit === 'acme' && !effectiveApply) {
        message.error("ssl.mode='acme' requires Apply Immediately (M22)");
        return;
      }
      // Phase F: inject the ACL builder's three rule arrays into the
      // wizard create payload. The builder lives outside the antd
      // Form so its state has to be merged in explicitly here.
      // FrontendStep validator (`https_redirect` ⊕ `redirect_rules`)
      // catches a non-empty redirect rule list combined with the
      // https_redirect=true switch with a clear 422 — surface that
      // earlier as a UX message so the operator sees it without a
      // round-trip.
      const aclRules = aclBuilderData.aclRules || [];
      const useBackendRules = aclBuilderData.useBackendRules || [];
      const redirectRules = aclBuilderData.redirectRules || [];
      if (values.frontend?.https_redirect && redirectRules.length) {
        message.error(
          'HTTP→HTTPS redirect cannot be combined with custom redirect rules. ' +
          'Either disable the switch on the Frontend step or remove the rules from the ACL builder.',
        );
        return;
      }
      values.frontend = {
        ...(values.frontend || {}),
        acl_rules: aclRules,
        use_backend_rules: useBackendRules,
        redirect_rules: redirectRules,
      };
      setSubmitting(true);
      const res = await axios.post('/api/sites', values);
      const { status, version_name, acme_order_id, acme_staging_error, apply_result } = res.data || {};

      if (status === 'created_applied') {
        message.success('Site created and applied successfully');
        if (acme_order_id) message.info(`ACME order #${acme_order_id} staged; agent confirmation pending`, 8);
        navigate('/frontends');
      } else if (status === 'created_pending') {
        message.success(`Site created (PENDING version ${version_name}). Open Apply Changes to deploy.`);
        navigate('/apply-management');
      } else if (status === 'created_pending_apply_failed') {
        // R18b audit fix (H): surface the apply error so the operator
        // can fix the cause (HAProxy parse error, missing CA file,
        // ssl_verify mismatch, etc.) instead of silently navigating
        // to Apply Changes with a generic "try again" message.
        const applyErr =
          apply_result?.error ||
          apply_result?.message ||
          (typeof apply_result === 'string' ? apply_result : '') ||
          '(no detail returned)';
        Modal.warning({
          title: 'Created but Apply Failed',
          width: 640,
          content: (
            <>
              <div>The wizard created the entities but the Apply step failed.</div>
              <div style={{ marginTop: 8 }}>
                <strong>Apply error:</strong>
                <pre style={{ marginTop: 4, padding: 8, background: '#fafafa', border: '1px solid #f0f0f0', whiteSpace: 'pre-wrap', fontSize: 12 }}>
                  {String(applyErr)}
                </pre>
              </div>
              <div style={{ marginTop: 8 }}>
                You can retry from <strong>Apply Changes</strong> after fixing the underlying issue.
              </div>
            </>
          ),
        });
        navigate('/apply-management');
      } else if (status === 'applied_acme_staging_failed') {
        Modal.warning({
          title: 'Applied but ACME staging failed',
          content: `Entities applied successfully but ACME staging failed: ${acme_staging_error}. You can manually request a certificate from ACME Automation.`,
        });
        navigate('/frontends');
      } else {
        message.success('Site created');
        navigate('/frontends');
      }
    } catch (err) {
      // R16 #v3: prefer the API envelope extractor; fall back to Antd
      // form validation errors when the rejection came from the local
      // validateFields() (no HTTP response).
      if (err?.errorFields) {
        const firstField = err.errorFields[0];
        message.error(`${firstField.name.join('.')}: ${firstField.errors[0]}`);
      } else {
        message.error(extractApiError(err, 'Submit failed'));
      }
    } finally {
      setSubmitting(false);
    }
  };

  // ---------- Save Draft ----------
  const handleSaveDraft = async () => {
    // R14 #v6 fix: surface the result to callers so handleCancel can avoid
    // navigating to /proxied-hosts/drafts when the save itself failed (was
    // shipping the user to an empty drafts list with a confusing error
    // toast). Returns true on success, false on failure.
    try {
      const payload = form.getFieldsValue(true);
      // Phase F: persist the ACL builder's rule arrays alongside the
      // form payload so a resumed draft hydrates with the same
      // routing rules the operator had already configured. The
      // resume flow on mount reads `frontend.acl_rules`,
      // `use_backend_rules` and `redirect_rules` back out.
      payload.frontend = {
        ...(payload.frontend || {}),
        acl_rules: aclBuilderData.aclRules || [],
        use_backend_rules: aclBuilderData.useBackendRules || [],
        redirect_rules: aclBuilderData.redirectRules || [],
      };
      const res = await axios.post('/api/sites/drafts', {
        title: payload?.frontend?.name || payload?.backend?.name || 'Untitled draft',
        payload,
      });
      message.success(`Draft saved (id ${res.data?.id})`);
      return true;
    } catch (err) {
      // R16 #v3: envelope-aware. The 256KB / 50-drafts cap (R14) and
      // the validation 422s all surface here.
      message.error(extractApiError(err, 'Save draft failed'));
      return false;
    }
  };

  const handleCancel = () => {
    Modal.confirm({
      title: 'Discard wizard?',
      content: 'You have unsaved changes. Save as draft or discard?',
      okText: 'Discard',
      cancelText: 'Save Draft',
      // R18c round 10 (M4): pre-round-10 the modal could be dismissed
      // by Esc or backdrop click, both of which Ant Design routes
      // through `onCancel` — silently triggering the Save Draft path.
      // Operators who hit Esc to "abort" ended up with a draft saved
      // and a navigation away from the wizard. Force the user to make
      // an explicit choice (Discard vs Save Draft) by disabling both
      // the keyboard escape and the masked-area click. The X close
      // button still appears in the corner for accidental opens; on
      // X it falls through to onCancel like Esc did, but that is the
      // documented "abort" affordance and acceptable.
      keyboard: false,
      maskClosable: false,
      onOk: () => navigate('/frontends'),
      onCancel: async () => {
        // R14 #v6 fix: only navigate away if the save actually succeeded.
        // If handleSaveDraft fails (network, 422 size-limit, 409 too many
        // drafts) we keep the user on the wizard so they don't lose their
        // in-flight work. The error toast is already raised inside
        // handleSaveDraft.
        const ok = await handleSaveDraft();
        if (ok) {
          // R18: navigate to the canonical /sites/drafts. Legacy
          // /quick-setup/drafts and /proxied-hosts/drafts still resolve
          // for bookmarked URLs but new navigations target the rebrand.
          navigate('/sites/drafts');
        }
      },
    });
  };

  // ---------- Step content ----------
  const stepContents = [
    {
      title: 'Cluster & Domains',
      content: (
        <>
          {/* Phase K Phase D (Bulgu #1): cluster is sourced from the
              header context (same as every other entity page). The
              hidden Form.Item keeps the value in form state for the
              submit payload and for `watchedClusterId`-driven fetches
              (existing certs, cluster backends). Above it, a read-
              only display card shows the active cluster so the
              operator always sees which cluster their wizard run
              will target. Mid-wizard cluster changes happen via the
              header — the existing cluster-transition cleanup
              effect clears stale per-cluster cert ids. */}
          <Form.Item
            name="cluster_id"
            hidden
            rules={[{ required: true, message: 'Select a cluster on the header' }]}
          >
            <Input type="hidden" />
          </Form.Item>
          <Form.Item label="Cluster">
            {selectedCluster ? (
              <Space size="small" align="center">
                <Tag color="blue" style={{ fontSize: 13, padding: '2px 10px' }}>
                  {selectedCluster.name}
                </Tag>
                <span style={{ color: '#888', fontSize: 12 }}>
                  Change via the cluster picker in the header.
                </span>
              </Space>
            ) : (
              <Alert
                type="warning"
                showIcon
                message="No cluster selected"
                description="Open the cluster picker in the header (top of the page) and select the target cluster before continuing."
              />
            )}
          </Form.Item>
          <Form.Item
            name="domains"
            label="Domain Names"
            rules={[
              { required: true, message: 'Enter at least one domain' },
              antdDomainsListRule,
            ]}
          >
            <Select
              mode="tags"
              placeholder="e.g. example.com, www.example.com"
              tokenSeparators={[',', ' ']}
              onChange={fetchSuggestions}
            />
          </Form.Item>
        </>
      ),
    },
    {
      title: 'Backend & Servers',
      content: (
        <>
          <Form.Item
            name={['backend', 'name']}
            label="Backend Name"
            rules={[
              { required: true, message: 'Required' },
              { pattern: /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/, message: 'Letters/digits/_/- only, must not start with _' },
            ]}
          >
            <Input placeholder="be-myapp" />
          </Form.Item>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name={['backend', 'balance_method']}
                label={
                  <Space>
                    <span>Load-balance algorithm</span>
                    <Tooltip title="HAProxy 2.4+ algorithms. roundrobin/leastconn for HTTP, source/uri for sticky distribution, hdr/url_param for header- or query-aware balancing.">
                      <ExclamationCircleOutlined />
                    </Tooltip>
                  </Space>
                }
              >
                <Select>
                  <Option value="roundrobin">roundrobin</Option>
                  <Option value="leastconn">leastconn</Option>
                  <Option value="static-rr">static-rr</Option>
                  <Option value="first">first</Option>
                  <Option value="source">source (sticky by IP)</Option>
                  <Option value="uri">uri (consistent hash on URI)</Option>
                  <Option value="random">random</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name={['backend', 'mode']} label="Mode">
                <Select>
                  <Option value="http">http (L7)</Option>
                  <Option value="tcp">tcp (L4)</Option>
                </Select>
              </Form.Item>
            </Col>
          </Row>

          {/* Health-check basics — visible to all users */}
          <Form.Item shouldUpdate>
            {() => {
              const beMode = form.getFieldValue(['backend', 'mode']);
              if (beMode === 'tcp') {
                return (
                  <Alert
                    type="info"
                    showIcon
                    style={{ marginBottom: 12 }}
                    message="TCP backends do not use health_check_uri. The default-server check directive is used; tune via Advanced settings."
                  />
                );
              }
              return (
                <Row gutter={16}>
                  <Col span={12}>
                    <Form.Item name={['backend', 'health_check_uri']} label="Health Check URI">
                      <Input placeholder="/" />
                    </Form.Item>
                  </Col>
                  <Col span={6}>
                    <Form.Item name={['backend', 'health_check_interval']} label="Interval (ms)">
                      <InputNumber min={100} step={500} style={{ width: '100%' }} />
                    </Form.Item>
                  </Col>
                  <Col span={6}>
                    <Form.Item name={['backend', 'health_check_expected_status']} label="Expected status">
                      <InputNumber min={100} max={599} style={{ width: '100%' }} />
                    </Form.Item>
                  </Col>
                </Row>
              );
            }}
          </Form.Item>

          {/* Backend Advanced — collapsed by default */}
          <Collapse
            ghost
            items={[{
              key: 'backend-adv',
              label: <Space><SettingOutlined /><span>Advanced backend settings</span></Space>,
              children: (
                <>
                  <Row gutter={16}>
                    <Col span={8}>
                      <Form.Item name={['backend', 'timeout_connect']} label="timeout connect (ms)">
                        <InputNumber min={100} step={1000} style={{ width: '100%' }} />
                      </Form.Item>
                    </Col>
                    <Col span={8}>
                      <Form.Item name={['backend', 'timeout_server']} label="timeout server (ms)">
                        <InputNumber min={100} step={1000} style={{ width: '100%' }} />
                      </Form.Item>
                    </Col>
                    <Col span={8}>
                      <Form.Item name={['backend', 'timeout_queue']} label="timeout queue (ms)">
                        <InputNumber min={100} step={1000} style={{ width: '100%' }} />
                      </Form.Item>
                    </Col>
                  </Row>
                  <Row gutter={16}>
                    <Col span={8}>
                      <Form.Item name={['backend', 'fullconn']} label="fullconn">
                        <InputNumber min={0} step={100} style={{ width: '100%' }} placeholder="(unset)" />
                      </Form.Item>
                    </Col>
                    <Col span={8}>
                      <Form.Item name={['backend', 'cookie_name']} label="Sticky cookie name">
                        <Input placeholder="SRVID" />
                      </Form.Item>
                    </Col>
                    <Col span={8}>
                      <Form.Item name={['backend', 'cookie_options']} label="Cookie options">
                        <Input placeholder="insert indirect nocache" />
                      </Form.Item>
                    </Col>
                  </Row>
                  <Divider>default-server defaults (applied to every server)</Divider>
                  <Row gutter={16}>
                    <Col span={8}>
                      <Form.Item name={['backend', 'default_server_inter']} label="default-server inter (ms)">
                        <InputNumber min={0} step={500} style={{ width: '100%' }} />
                      </Form.Item>
                    </Col>
                    <Col span={8}>
                      <Form.Item name={['backend', 'default_server_fall']} label="default-server fall">
                        <InputNumber min={0} style={{ width: '100%' }} />
                      </Form.Item>
                    </Col>
                    <Col span={8}>
                      <Form.Item name={['backend', 'default_server_rise']} label="default-server rise">
                        <InputNumber min={0} style={{ width: '100%' }} />
                      </Form.Item>
                    </Col>
                  </Row>
                  <Form.Item name={['backend', 'request_headers']} label="Request headers (one directive per line)">
                    <Input.TextArea rows={3} placeholder="http-request set-header X-Forwarded-For %[src]" />
                  </Form.Item>
                  <Form.Item name={['backend', 'response_headers']} label="Response headers">
                    <Input.TextArea rows={3} placeholder="http-response set-header X-Powered-By haproxy-openmanager" />
                  </Form.Item>
                  <Form.Item
                    name={['backend', 'options']}
                    label="Raw HAProxy options (one per line; option httpchk auto-stripped)"
                  >
                    <Input.TextArea rows={3} placeholder="option forwardfor&#10;option redispatch" />
                  </Form.Item>
                </>
              ),
            }]}
          />

          <Divider>Servers</Divider>
          <Form.List name="servers">
            {(fields, { add, remove }) => (
              <>
                {fields.map(({ key, name, ...rest }) => (
                  <Card key={key} size="small" style={{ marginBottom: 8 }} bodyStyle={{ padding: 12 }}>
                    <Row gutter={8} align="middle">
                      <Col span={5}>
                        <Form.Item
                          {...rest}
                          name={[name, 'server_name']}
                          label="Name"
                          rules={[{ required: true, message: 'Required' }]}
                        >
                          <Input placeholder="srv1" />
                        </Form.Item>
                      </Col>
                      <Col span={8}>
                        <Form.Item
                          {...rest}
                          name={[name, 'server_address']}
                          label="Address"
                          rules={[{ required: true, message: 'Required' }]}
                        >
                          <Input placeholder="10.0.0.1 / app.local" />
                        </Form.Item>
                      </Col>
                      <Col span={3}>
                        <Form.Item
                          {...rest}
                          name={[name, 'server_port']}
                          label="Port"
                          rules={[{ required: true, message: 'Required' }]}
                        >
                          <InputNumber min={1} max={65535} style={{ width: '100%' }} />
                        </Form.Item>
                      </Col>
                      <Col span={3}>
                        {/* Antd warns when initialValue is set on a
                            Form.Item inside Form.List. Defaults are
                            supplied by Form's initialValues (servers[0])
                            and by the add() helper for new rows. */}
                        <Form.Item {...rest} name={[name, 'weight']} label="Weight">
                          <InputNumber min={0} max={256} style={{ width: '100%' }} />
                        </Form.Item>
                      </Col>
                      <Col span={3}>
                        <Form.Item {...rest} name={[name, 'check_enabled']} label="Check" valuePropName="checked">
                          <Switch />
                        </Form.Item>
                      </Col>
                      <Col span={2} style={{ textAlign: 'right' }}>
                        {fields.length > 1 && (
                          <Button type="text" danger icon={<MinusCircleOutlined />} onClick={() => remove(name)} />
                        )}
                      </Col>
                    </Row>

                    {/* Per-server advanced (collapsible) */}
                    <Collapse
                      ghost
                      items={[{
                        key: `srv-adv-${key}`,
                        label: <Space><SettingOutlined /><span>Advanced server settings</span></Space>,
                        children: (
                          <>
                            <Row gutter={16}>
                              <Col span={6}>
                                <Form.Item {...rest} name={[name, 'inter']} label="check inter (ms)">
                                  <InputNumber min={0} step={500} style={{ width: '100%' }} placeholder="default" />
                                </Form.Item>
                              </Col>
                              <Col span={6}>
                                <Form.Item {...rest} name={[name, 'fall']} label="fall">
                                  <InputNumber min={0} style={{ width: '100%' }} placeholder="default" />
                                </Form.Item>
                              </Col>
                              <Col span={6}>
                                <Form.Item {...rest} name={[name, 'rise']} label="rise">
                                  <InputNumber min={0} style={{ width: '100%' }} placeholder="default" />
                                </Form.Item>
                              </Col>
                              <Col span={6}>
                                <Form.Item {...rest} name={[name, 'check_port']} label="check port">
                                  <InputNumber min={1} max={65535} style={{ width: '100%' }} placeholder="(use server port)" />
                                </Form.Item>
                              </Col>
                            </Row>
                            <Row gutter={16}>
                              <Col span={8}>
                                <Form.Item {...rest} name={[name, 'max_connections']} label="maxconn">
                                  <InputNumber min={0} step={100} style={{ width: '100%' }} />
                                </Form.Item>
                              </Col>
                              <Col span={8}>
                                <Form.Item {...rest} name={[name, 'backup_server']} label="backup" valuePropName="checked">
                                  <Switch />
                                </Form.Item>
                              </Col>
                              <Col span={8}>
                                <Form.Item
                                  shouldUpdate={(prev, curr) =>
                                    prev?.backend?.cookie_name !==
                                    curr?.backend?.cookie_name
                                  }
                                  noStyle
                                >
                                  {() => {
                                    const backendCookieName = form.getFieldValue(['backend', 'cookie_name']);
                                    const cookieEnabled = !!(backendCookieName && String(backendCookieName).trim());
                                    return (
                                      <Form.Item
                                        {...rest}
                                        name={[name, 'cookie_value']}
                                        label="Sticky cookie value"
                                        extra={
                                          cookieEnabled
                                            ? undefined
                                            : 'Requires "Sticky cookie name" on the backend block above. Otherwise this value is silently dropped at config render time.'
                                        }
                                      >
                                        <Input
                                          placeholder="srv1"
                                          disabled={!cookieEnabled}
                                        />
                                      </Form.Item>
                                    );
                                  }}
                                </Form.Item>
                              </Col>
                            </Row>
                            <Divider plain>SSL/TLS to backend (server ssl)</Divider>
                            <Row gutter={16}>
                              <Col span={6}>
                                <Form.Item {...rest} name={[name, 'ssl_enabled']} label="Enable SSL" valuePropName="checked">
                                  <Switch />
                                </Form.Item>
                              </Col>
                              <Col span={6}>
                                <Form.Item {...rest} name={[name, 'ssl_verify']} label="ssl_verify">
                                  <Select allowClear placeholder="(none)">
                                    <Option value="none">none</Option>
                                    <Option value="required">required</Option>
                                  </Select>
                                </Form.Item>
                              </Col>
                              <Col span={12}>
                                <Form.Item {...rest} name={[name, 'ssl_sni']} label="ssl_sni">
                                  <Input placeholder="api.example.com" />
                                </Form.Item>
                              </Col>
                            </Row>
                            <Row gutter={16}>
                              <Col span={8}>
                                {/* R18c round 10 (M1): pre-round-10 the
                                    wizard offered TLSv1.0 / TLSv1.1 as
                                    "legacy upstream" options to mirror the
                                    backend's permissive Literal accept.
                                    The model_post_validator on ServerStep
                                    (models/site_wizard.py) however
                                    rejects them outright per RFC 8996, so
                                    a user picking a 1.0/1.1 entry only
                                    discovered the rejection via a 422 at
                                    submit time after navigating five
                                    wizard steps. Drop the legacy options
                                    from the UI to match the backend
                                    contract; an operator with a hard
                                    requirement can still author the
                                    backend through the regular Backends
                                    UI which uses an unrestricted path. */}
                                <Form.Item {...rest} name={[name, 'ssl_min_ver']} label="TLS min">
                                  <Select allowClear placeholder="(default)">
                                    <Option value="TLSv1.2">TLSv1.2</Option>
                                    <Option value="TLSv1.3">TLSv1.3</Option>
                                  </Select>
                                </Form.Item>
                              </Col>
                              <Col span={8}>
                                <Form.Item {...rest} name={[name, 'ssl_max_ver']} label="TLS max">
                                  <Select allowClear placeholder="(default)">
                                    <Option value="TLSv1.2">TLSv1.2</Option>
                                    <Option value="TLSv1.3">TLSv1.3</Option>
                                  </Select>
                                </Form.Item>
                              </Col>
                              <Col span={8}>
                                <Form.Item {...rest} name={[name, 'ssl_ciphers']} label="ciphers">
                                  <Input placeholder="HIGH:!aNULL:!MD5" />
                                </Form.Item>
                              </Col>
                            </Row>
                            {/* R17 minimum-parity (label corrected in R18):
                                this maps to HAProxy's `ca-file` directive on
                                the server line — i.e. the CA bundle HAProxy
                                uses to VERIFY the backend server's TLS
                                certificate when ssl_verify='required'. The
                                manual BackendServers UI exposes the same
                                field as a generic "SSL Certificate" Select
                                (BackendServers.js:2147). Pre-R18 the label
                                said "Client cert (mTLS to server)" which
                                wrongly suggested HAProxy presents this cert
                                — the actual semantics is CA verification. */}
                            <Form.Item shouldUpdate={(prev, cur) => {
                              const p = prev?.servers?.[name]?.ssl_enabled;
                              const c = cur?.servers?.[name]?.ssl_enabled;
                              const pv = prev?.servers?.[name]?.ssl_verify;
                              const cv = cur?.servers?.[name]?.ssl_verify;
                              return p !== c || pv !== cv;
                            }} noStyle>
                              {({ getFieldValue }) => {
                                const sslOn = !!getFieldValue(['servers', name, 'ssl_enabled']);
                                const verifyMode = getFieldValue(['servers', name, 'ssl_verify']);
                                const required = verifyMode === 'required';
                                return (
                                  <Form.Item
                                    {...rest}
                                    name={[name, 'ssl_certificate_id']}
                                    label="CA bundle for upstream verification"
                                    tooltip="HAProxy `ca-file` directive: the CA bundle used to verify the upstream server's TLS certificate. Required when ssl_verify='required'."
                                    rules={required ? [{ required: true, message: 'A CA bundle is required when ssl_verify is "required"' }] : []}
                                  >
                                    <Select
                                      allowClear
                                      placeholder={sslOn ? "(none — skip server cert verification)" : "Enable SSL to backend first"}
                                      disabled={!sslOn}
                                      showSearch
                                      optionFilterProp="children"
                                    >
                                      {/* Phase K Phase D (Bulgu #2): the
                                          "CA bundle for upstream
                                          verification" field maps to
                                          HAProxy's `ca-file` server-line
                                          directive. The matching backend
                                          page (BackendServers.js:221)
                                          filters its options to certs
                                          tagged usage_type='server' so the
                                          operator does NOT see frontend
                                          (HTTPS bind) certs that would
                                          parse-error at apply time. The
                                          wizard pre-fix surfaced every
                                          cert in the cluster, breaking
                                          parity AND violating the SSL
                                          import contract (usage_type
                                          drives WHICH HAProxy slot the
                                          cert is allowed to occupy).
                                          Filter explicitly here. */}
                                      {existingCerts
                                        .filter((c) => c.usage_type === 'server')
                                        .map((c) => (
                                        <Option key={c.id} value={c.id}>
                                          {c.name}{c.primary_domain ? ` — ${c.primary_domain}` : ''}
                                        </Option>
                                      ))}
                                    </Select>
                                  </Form.Item>
                                );
                              }}
                            </Form.Item>
                          </>
                        ),
                      }]}
                    />
                  </Card>
                ))}
                <Form.Item>
                  <Button
                    onClick={() => add({
                      server_name: `srv${fields.length + 1}`,
                      server_port: 8080,
                      weight: 100,
                      check_enabled: true,
                      ssl_enabled: false,
                    })}
                    icon={<PlusOutlined />}
                  >
                    Add server
                  </Button>
                </Form.Item>
              </>
            )}
          </Form.List>
        </>
      ),
    },
    {
      title: 'Frontend',
      content: (
        <>
          <Form.Item
            name={['frontend', 'name']}
            label="Frontend Name"
            rules={[
              { required: true, message: 'Required' },
              { pattern: /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/, message: 'Letters/digits/_/- only, must not start with _' },
            ]}
          >
            <Input placeholder="fe-myapp" />
          </Form.Item>
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item name={['frontend', 'mode']} label="Mode">
                <Select>
                  <Option value="http">http (L7)</Option>
                  <Option value="tcp">tcp (L4)</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name={['frontend', 'bind_address']} label="Bind Address" initialValue="*">
                <Input placeholder="*" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name={['frontend', 'bind_port']} label="Bind Port" initialValue={80}>
                <InputNumber min={1} max={65535} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name={['frontend', 'https_redirect']} label="HTTP -> HTTPS redirect" valuePropName="checked">
            <Tooltip
              title={
                watchedFrontendMode === 'tcp'
                  ? 'HTTP→HTTPS redirect requires HTTP mode (L7). TCP frontends operate at L4 and cannot inspect HTTP headers — the wizard auto-clears this when you switch to TCP.'
                  : ''
              }
            >
              <Switch
                disabled={watchedFrontendMode === 'tcp'}
                aria-disabled={watchedFrontendMode === 'tcp'}
              />
            </Tooltip>
          </Form.Item>
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 12 }}
            message="If enabled, the wizard will inject a 301 redirect to https://. Cannot be combined with custom redirect_rules in this wizard step."
          />

          {/* Phase F: Routing & ACLs — list-based ACL builder, identical
              to the standalone Frontend Management page so the wizard
              UX matches manual frontend creation. Hidden when the
              frontend mode is TCP because L4 cannot match L7 ACLs. */}
          {watchedFrontendMode !== 'tcp' && (
            <Collapse
              ghost
              defaultActiveKey={
                aclBuilderData.aclRules.length ||
                aclBuilderData.useBackendRules.length ||
                aclBuilderData.redirectRules.length
                  ? ['fe-acl']
                  : []
              }
              items={[{
                key: 'fe-acl',
                label: (
                  <Space>
                    <FilterOutlined />
                    <span>Routing &amp; ACLs (Access Control Lists)</span>
                    {(aclBuilderData.aclRules.length +
                      aclBuilderData.useBackendRules.length +
                      aclBuilderData.redirectRules.length) > 0 && (
                      <Tag color="blue">
                        {aclBuilderData.aclRules.length} ACL ·{' '}
                        {aclBuilderData.useBackendRules.length} route ·{' '}
                        {aclBuilderData.redirectRules.length} redirect
                      </Tag>
                    )}
                  </Space>
                ),
                children: (
                  <>
                    <Alert
                      type="info"
                      showIcon
                      style={{ marginBottom: 12 }}
                      message={
                        <span>
                          Optional. Define <strong>ACL rules</strong> to match
                          HTTP traffic, then route matches to a different{' '}
                          <strong>backend</strong> or apply a{' '}
                          <strong>redirect</strong>. The wizard&rsquo;s
                          new backend is included in the dropdown
                          alongside other backends in this cluster.
                        </span>
                      }
                    />
                    {watchedHttpsRedirect && aclBuilderData.redirectRules.length > 0 && (
                      <Alert
                        type="error"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message="HTTP→HTTPS redirect cannot be combined with custom redirect rules"
                        description="The switch above already publishes a 301 redirect on port 80; the rules here are mutually exclusive with it. Choose one of the two paths below before continuing."
                        action={
                          <Space direction="vertical" size={4}>
                            <Button
                              size="small"
                              danger
                              onClick={() =>
                                form.setFields([
                                  { name: ['frontend', 'https_redirect'], value: false },
                                ])
                              }
                            >
                              Disable HTTP→HTTPS switch
                            </Button>
                            <Button
                              size="small"
                              onClick={() =>
                                setAclBuilderData((prev) => ({
                                  ...prev,
                                  redirectRules: [],
                                }))
                              }
                            >
                              Remove redirect rules
                            </Button>
                          </Space>
                        }
                      />
                    )}
                    <ACLRuleBuilder
                      key={aclBuilderKey}
                      aclRules={aclBuilderData.aclRules}
                      useBackendRules={aclBuilderData.useBackendRules}
                      redirectRules={aclBuilderData.redirectRules}
                      backends={aclBuilderBackends}
                      disableRedirectRules={!!watchedHttpsRedirect}
                      onChange={(data) => setAclBuilderData(data)}
                    />
                  </>
                ),
              }]}
            />
          )}

          {/* Frontend Advanced */}
          <Collapse
            ghost
            items={[{
              key: 'fe-adv',
              label: <Space><SettingOutlined /><span>Advanced frontend settings</span></Space>,
              children: (
                <>
                  <Row gutter={16}>
                    <Col span={6}>
                      <Form.Item name={['frontend', 'maxconn']} label="maxconn">
                        <InputNumber min={1} step={1000} style={{ width: '100%' }} placeholder="(unset)" />
                      </Form.Item>
                    </Col>
                    <Col span={6}>
                      <Form.Item name={['frontend', 'rate_limit']} label="rate-limit (req/s)">
                        <InputNumber min={0} step={10} style={{ width: '100%' }} placeholder="(unset)" />
                      </Form.Item>
                    </Col>
                    <Col span={6}>
                      <Form.Item name={['frontend', 'timeout_client']} label="timeout client (ms)">
                        <InputNumber min={100} step={1000} style={{ width: '100%' }} placeholder="default" />
                      </Form.Item>
                    </Col>
                    <Col span={6}>
                      <Form.Item name={['frontend', 'timeout_http_request']} label="timeout http-request (ms)">
                        <InputNumber min={100} step={1000} style={{ width: '100%' }} placeholder="default" />
                      </Form.Item>
                    </Col>
                  </Row>
                  <Row gutter={16}>
                    <Col span={8}>
                      <Form.Item name={['frontend', 'compression']} label="gzip compression" valuePropName="checked">
                        <Switch />
                      </Form.Item>
                    </Col>
                    <Col span={8}>
                      <Form.Item name={['frontend', 'log_separate']} label="log-separate" valuePropName="checked">
                        <Switch />
                      </Form.Item>
                    </Col>
                    <Col span={8}>
                      <Form.Item name={['frontend', 'monitor_uri']} label="monitor-uri">
                        <Input placeholder="/haproxy-status" />
                      </Form.Item>
                    </Col>
                  </Row>
                  <Form.Item name={['frontend', 'request_headers']} label="Request headers (HAProxy syntax, one directive per line)">
                    <Input.TextArea rows={3} placeholder='http-request set-header X-Real-IP %[src]' />
                  </Form.Item>
                  <Form.Item name={['frontend', 'response_headers']} label="Response headers">
                    <Input.TextArea rows={3} placeholder='http-response set-header X-Frame-Options DENY' />
                  </Form.Item>
                  <Form.Item
                    name={['frontend', 'options']}
                    label="Raw HAProxy options"
                  >
                    <Input.TextArea rows={3} placeholder="option httplog&#10;option dontlognull" />
                  </Form.Item>
                  <Form.Item shouldUpdate>
                    {() => {
                      const feMode = form.getFieldValue(['frontend', 'mode']);
                      if (feMode === 'tcp') {
                        return (
                          <Form.Item name={['frontend', 'tcp_request_rules']} label="tcp-request rules (TCP mode only)">
                            <Input.TextArea rows={3} placeholder="tcp-request inspect-delay 5s&#10;tcp-request content accept if { req_ssl_hello_type 1 }" />
                          </Form.Item>
                        );
                      }
                      return null;
                    }}
                  </Form.Item>
                </>
              ),
            }]}
          />
        </>
      ),
    },
    {
      title: 'SSL & ACME',
      content: (
        <>
          {/* Phase K Phase D follow-up (Bulgu #14) — surface a
              persistent in-page banner when the orphan-clean
              effect wiped a referenced cert. Toast-only
              notifications are easy to miss on a busy
              dashboard; this Alert stays visible until the
              operator picks a replacement / switches mode.
              Dismissed automatically when the operator changes
              ssl.mode below. */}
          {orphanClearedCerts.length > 0 && (
            <Alert
              type="warning"
              showIcon
              closable
              onClose={() => setOrphanClearedCerts([])}
              style={{ marginBottom: 12 }}
              message="Previously selected SSL certificate is no longer available"
              description={
                <>
                  <div>
                    The certificate(s) referenced by your saved draft
                    have been removed from the cluster (deleted /
                    deactivated) since the draft was saved:
                  </div>
                  <ul style={{ marginTop: 6, marginBottom: 6 }}>
                    {orphanClearedCerts.map((o) => (
                      <li key={o}><code>{o}</code></li>
                    ))}
                  </ul>
                  <div>
                    SSL mode has been reverted to <code>none</code> so the
                    wizard can proceed. Pick a replacement certificate
                    below, or switch to <code>upload</code> / <code>acme</code> mode.
                  </div>
                </>
              }
            />
          )}
          <Form.Item name={['ssl', 'mode']} label="SSL Mode" initialValue="none">
            <Select
              onChange={() => {
                setPreflightResults(null);
                // Bulgu #14 — dismiss the orphan banner once the
                // operator explicitly picks a mode. They've now
                // acknowledged the state.
                if (orphanClearedCerts.length) setOrphanClearedCerts([]);
              }}
            >
              {SSL_MODES.map((m) => (
                <Option key={m.value} value={m.value}>
                  {m.label} — <span style={{ color: '#888' }}>{m.description}</span>
                </Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item shouldUpdate>
            {() => {
              const sslMode = form.getFieldValue(['ssl', 'mode']);
              if (sslMode === 'upload') {
                return (
                  <>
                    <Form.Item name={['ssl', 'name']} label="Certificate Name" rules={[{ required: true }]}>
                      <Input placeholder="cert-myapp" />
                    </Form.Item>
                    <Form.Item name={['ssl', 'certificate_content']} label="Certificate (PEM)" rules={[{ required: true }]}>
                      <Input.TextArea rows={6} placeholder="-----BEGIN CERTIFICATE-----..." />
                    </Form.Item>
                    <Form.Item name={['ssl', 'private_key_content']} label="Private Key (PEM)" rules={[{ required: true }]}>
                      <Input.TextArea rows={6} placeholder="-----BEGIN PRIVATE KEY-----..." />
                    </Form.Item>
                    <Form.Item name={['ssl', 'chain_content']} label="Chain (PEM, optional)">
                      <Input.TextArea rows={4} />
                    </Form.Item>
                  </>
                );
              }
              if (sslMode === 'existing') {
                // R18 UX: tell the user explicitly when the list is empty
                // because no cluster is picked vs. because the cluster
                // genuinely has no imported certs. Otherwise an empty
                // dropdown looks broken (see Issue #14 follow-up).
                const hasCluster = !!watchedClusterId;
                // Phase K Phase D (Bulgu #2): the empty-state alert
                // must consider ONLY frontend-usage certs, otherwise
                // a cluster with N server-side ca-file certs but
                // zero HTTPS-bind certs would render a "select an
                // existing certificate" dropdown that is in fact
                // empty (filtered out below) with no explanatory
                // alert.
                const frontendCertsForCluster = existingCerts.filter(
                  (c) => c.usage_type === 'frontend',
                );
                const noCertsForCluster = hasCluster && frontendCertsForCluster.length === 0;
                return (
                  <>
                    {!hasCluster && (
                      <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 8 }}
                        message="Pick a cluster on Step 1 first — the existing-certificate list is filtered to the cluster's certs (plus any global ones)."
                      />
                    )}
                    {noCertsForCluster && (
                      <Alert
                        type="warning"
                        showIcon
                        style={{ marginBottom: 8 }}
                        message="No imported SSL certificates are visible for this cluster."
                        description="Either upload a new cert via 'Upload PEM' above, switch to ACME, or import a cert from the SSL Certificates page (cluster-specific or global)."
                      />
                    )}
                    <Form.Item
                      name={['ssl', 'ssl_certificate_id']}
                      label="Existing certificate"
                      rules={[{ required: true }]}
                    >
                      <Select
                        placeholder={hasCluster ? 'Select an existing certificate' : 'Select a cluster first'}
                        disabled={!hasCluster}
                        showSearch
                        optionFilterProp="children"
                        notFoundContent={hasCluster ? 'No frontend certificates for this cluster' : 'Select a cluster first'}
                      >
                        {/* Phase K Phase D (Bulgu #2): mirror the
                            BackendServers usage_type filter on the
                            HTTPS-frontend side. This Select binds the
                            cert to the HTTPS frontend's `crt` slot —
                            HAProxy expects a server-presented cert,
                            i.e. usage_type='frontend'. Surfacing
                            server-side (`ca-file`) certs here would
                            let an operator submit a payload that
                            apply-time HAProxy would parse-error on
                            (`unable to load SSL private key from PEM
                            file`). Filter matches BackendServers'
                            implicit contract. */}
                        {frontendCertsForCluster.map((c) => (
                          <Option key={c.id} value={c.id}>
                            {c.name}{c.primary_domain ? ` — ${c.primary_domain}` : ''}{c.ssl_type ? ` [${c.ssl_type}]` : ''}
                          </Option>
                        ))}
                      </Select>
                    </Form.Item>
                  </>
                );
              }
              if (sslMode === 'acme') {
                return (
                  <>
                    <Alert
                      type="warning"
                      showIcon
                      message="ACME mode requires Apply Immediately"
                      description="The agent must confirm the new HTTP frontend before Let's Encrypt can validate the HTTP-01 challenge. The wizard will set apply_immediately=true automatically."
                    />

                    {/* ACME account & renewal advanced */}
                    {acmeAccounts.length > 1 && (
                      <Form.Item name={['ssl', 'account_id']} label="Let's Encrypt account" style={{ marginTop: 12 }}>
                        <Select
                          allowClear
                          placeholder={`Auto-select latest valid (${acmeAccounts.length} accounts available)`}
                        >
                          {acmeAccounts.map((a) => (
                            <Option key={a.id} value={a.id}>
                              {a.email || `account #${a.id}`} — <span style={{ color: '#888' }}>{a.directory_url || ''}</span>
                            </Option>
                          ))}
                        </Select>
                      </Form.Item>
                    )}
                    <Row gutter={16} style={{ marginTop: 12 }}>
                      <Col span={24}>
                        <Form.Item name={['ssl', 'auto_renew']} label="Auto-renew when expiring" valuePropName="checked">
                          <Switch />
                        </Form.Item>
                      </Col>
                    </Row>
                    {/* v1.5.0 R12: per-cert renew-before-days override is
                        not yet plumbed end-to-end (renewal scheduler still
                        reads global acme.renew_before_days). Keeping the
                        UI honest by NOT surfacing a placebo control. */}
                    <Alert
                      type="info"
                      showIcon
                      style={{ marginTop: 8, marginBottom: 12 }}
                      message="Wildcards (*.example.com) require DNS-01 challenge — not yet supported in this wizard. Use ACME Automation > Manual order for wildcards."
                    />

                    <div style={{ marginTop: 16 }}>
                      <Button type="primary" icon={<ReloadOutlined />} loading={preflightLoading} onClick={runPreflight}>
                        Run ACME pre-flight checks
                      </Button>
                    </div>
                    {preflightResults && (
                      <div style={{ marginTop: 16 }}>
                        {preflightResults.checks.map((c) => (
                          <Card key={c.id} size="small" style={{ marginBottom: 8 }}>
                            <Space>
                              {checkStatusToTag(c.status)}
                              <strong>{c.label}:</strong>
                              <span>{c.message}</span>
                            </Space>
                          </Card>
                        ))}
                        {preflightResults.checks.some((c) => c.status === 'warn' || c.status === 'fail') && (
                          <Alert
                            type={preflightResults.checks.some((c) => c.status === 'fail') ? 'error' : 'warning'}
                            showIcon
                            style={{ marginTop: 12 }}
                            message={preflightResults.checks.some((c) => c.status === 'fail')
                              ? 'Some pre-flight checks failed'
                              : 'Some pre-flight checks reported warnings'}
                            description={
                              <label>
                                <input
                                  type="checkbox"
                                  checked={continueAnyway}
                                  onChange={(e) => setContinueAnyway(e.target.checked)}
                                />{' '}
                                Continue anyway (override; e.g. egress port-80 false-positive in corporate networks)
                              </label>
                            }
                          />
                        )}
                      </div>
                    )}
                  </>
                );
              }
              return null;
            }}
          </Form.Item>

          {/* HTTPS frontend tuning — visible whenever HTTPS will be created.
              Phase K Phase D: only the security-shaping knobs (TLS bounds +
              HSTS quartet) stay visible at the top level. The rarely-used
              tuning (https_bind_port, https_frontend_name_suffix, ALPN,
              ciphers, ciphersuites, strict-sni, mTLS) moves into a nested
              "Advanced TLS settings (rarely needed)" Collapse that defaults
              to closed. The Advanced Collapse auto-opens when a saved draft
              has non-default values so resumed drafts surface their custom
              settings instead of hiding them silently. */}
          <Form.Item shouldUpdate>
            {() => {
              const sslMode = form.getFieldValue(['ssl', 'mode']);
              if (!['acme', 'upload', 'existing'].includes(sslMode)) return null;
              const sslVals = form.getFieldValue('ssl') || {};
              const advancedHasNonDefault =
                (sslVals.https_bind_port != null && sslVals.https_bind_port !== 443) ||
                (sslVals.https_frontend_name_suffix &&
                  sslVals.https_frontend_name_suffix !== '-https') ||
                (sslVals.ssl_alpn && sslVals.ssl_alpn !== 'h2,http/1.1') ||
                !!sslVals.ssl_ciphers ||
                !!sslVals.ssl_ciphersuites ||
                sslVals.ssl_strict_sni === true ||
                !!sslVals.ssl_verify;
              return (
                <Collapse
                  ghost
                  style={{ marginTop: 16 }}
                  items={[{
                    key: 'ssl-https-tuning',
                    label: <Space><LockOutlined /><span>HTTPS frontend tuning (TLS, HSTS)</span></Space>,
                    children: (
                      <>
                        {/* Read-only summary of the safe defaults that apply
                            unless the operator opens Advanced TLS settings. */}
                        <Alert
                          type="info"
                          showIcon
                          style={{ marginBottom: 12 }}
                          message="Safe defaults (apply unless overridden under Advanced TLS settings below)"
                          description="Port 443 · ALPN h2,http/1.1 · strict-sni off · modern HAProxy ciphers · mTLS disabled"
                        />
                        {/* TLS min/max — first-class controls because
                            they shape security posture. UI parity for the
                            min ≤ max rule from the Phase A
                            `reject_inverted_tls_versions` validator. */}
                        <Row gutter={16}>
                          <Col span={12}>
                            <Form.Item
                              name={['ssl', 'ssl_min_ver']}
                              label="TLS min version"
                              dependencies={[['ssl', 'ssl_max_ver']]}
                              rules={[
                                ({ getFieldValue }) => ({
                                  validator(_, value) {
                                    const max = getFieldValue(['ssl', 'ssl_max_ver']);
                                    if (!value || !max) return Promise.resolve();
                                    const order = { 'TLSv1.0': 0, 'TLSv1.1': 1, 'TLSv1.2': 2, 'TLSv1.3': 3 };
                                    if (order[value] > order[max]) {
                                      return Promise.reject(new Error(
                                        'TLS min version cannot be greater than TLS max version.'
                                      ));
                                    }
                                    return Promise.resolve();
                                  },
                                }),
                              ]}
                            >
                              <Select>
                                <Option value="TLSv1.2">TLSv1.2 (recommended)</Option>
                                <Option value="TLSv1.3">TLSv1.3 (modern)</Option>
                              </Select>
                            </Form.Item>
                          </Col>
                          <Col span={12}>
                            <Form.Item
                              name={['ssl', 'ssl_max_ver']}
                              label="TLS max version"
                              dependencies={[['ssl', 'ssl_min_ver']]}
                              rules={[
                                ({ getFieldValue }) => ({
                                  validator(_, value) {
                                    const min = getFieldValue(['ssl', 'ssl_min_ver']);
                                    if (!value || !min) return Promise.resolve();
                                    const order = { 'TLSv1.0': 0, 'TLSv1.1': 1, 'TLSv1.2': 2, 'TLSv1.3': 3 };
                                    if (order[min] > order[value]) {
                                      return Promise.reject(new Error(
                                        'TLS max version cannot be lower than TLS min version.'
                                      ));
                                    }
                                    return Promise.resolve();
                                  },
                                }),
                              ]}
                            >
                              <Select allowClear placeholder="(no max)">
                                <Option value="TLSv1.2">TLSv1.2</Option>
                                <Option value="TLSv1.3">TLSv1.3</Option>
                              </Select>
                            </Form.Item>
                          </Col>
                        </Row>

                        {/* HSTS quartet — UI parity for the Phase A backend
                            `reject_hsts_preload_without_hsts` validator's
                            three-way prerequisite. The dependencies wiring
                            disables `hsts_max_age` / `hsts_include_subdomains`
                            / `hsts_preload` while their prerequisites are
                            unmet so the operator cannot author an
                            unreachable state. */}
                        <Divider plain>HTTP Strict Transport Security (HSTS)</Divider>
                        <Form.Item shouldUpdate noStyle>
                          {() => {
                            const hstsEnabled = !!form.getFieldValue(['ssl', 'hsts_enabled']);
                            const hstsMaxAge = form.getFieldValue(['ssl', 'hsts_max_age']);
                            const hstsIncl = !!form.getFieldValue(['ssl', 'hsts_include_subdomains']);
                            const preloadOk =
                              hstsEnabled &&
                              hstsIncl &&
                              typeof hstsMaxAge === 'number' &&
                              hstsMaxAge >= 31536000;
                            const preloadTooltip = preloadOk
                              ? ''
                              : 'HSTS preload requires HSTS enabled, max-age ≥ 1 year (31536000 s), and includeSubDomains.';
                            return (
                              <Row gutter={16}>
                                <Col span={6}>
                                  <Form.Item name={['ssl', 'hsts_enabled']} label="Enable HSTS" valuePropName="checked">
                                    <Switch />
                                  </Form.Item>
                                </Col>
                                <Col span={6}>
                                  <Tooltip title={hstsEnabled ? '' : 'Enable HSTS first.'}>
                                    <Form.Item name={['ssl', 'hsts_max_age']} label="max-age (seconds)">
                                      <InputNumber
                                        min={0}
                                        step={31536000}
                                        style={{ width: '100%' }}
                                        disabled={!hstsEnabled}
                                        aria-disabled={!hstsEnabled || undefined}
                                      />
                                    </Form.Item>
                                  </Tooltip>
                                </Col>
                                <Col span={6}>
                                  <Tooltip title={hstsEnabled ? '' : 'Enable HSTS first.'}>
                                    <Form.Item name={['ssl', 'hsts_include_subdomains']} label="includeSubDomains" valuePropName="checked">
                                      <Switch
                                        disabled={!hstsEnabled}
                                        aria-disabled={!hstsEnabled || undefined}
                                      />
                                    </Form.Item>
                                  </Tooltip>
                                </Col>
                                <Col span={6}>
                                  <Tooltip title={preloadTooltip}>
                                    <Form.Item name={['ssl', 'hsts_preload']} label="preload" valuePropName="checked">
                                      <Switch
                                        disabled={!preloadOk}
                                        aria-disabled={!preloadOk || undefined}
                                      />
                                    </Form.Item>
                                  </Tooltip>
                                </Col>
                              </Row>
                            );
                          }}
                        </Form.Item>

                        {/* Advanced TLS settings — default closed Collapse.
                            Auto-opens when a saved draft has non-default
                            values so resumed drafts surface their tuning. */}
                        <Collapse
                          ghost
                          style={{ marginTop: 8 }}
                          defaultActiveKey={advancedHasNonDefault ? ['advanced-tls'] : []}
                          items={[{
                            key: 'advanced-tls',
                            label: (
                              <Space>
                                <SettingOutlined />
                                <span>Advanced TLS settings (rarely needed)</span>
                              </Space>
                            ),
                            children: (
                              <>
                                <Row gutter={16}>
                                  <Col span={8}>
                                    <Form.Item name={['ssl', 'https_bind_port']} label="HTTPS bind port">
                                      <InputNumber min={1} max={65535} style={{ width: '100%' }} />
                                    </Form.Item>
                                  </Col>
                                  <Col span={8}>
                                    <Form.Item name={['ssl', 'https_frontend_name_suffix']} label="Frontend name suffix">
                                      <Input placeholder="-https" />
                                    </Form.Item>
                                  </Col>
                                  <Col span={8}>
                                    <Form.Item name={['ssl', 'ssl_strict_sni']} label="strict-sni" valuePropName="checked">
                                      <Switch />
                                    </Form.Item>
                                  </Col>
                                </Row>
                                <Form.Item
                                  name={['ssl', 'ssl_alpn']}
                                  label="ALPN (HTTP/2 negotiation)"
                                  tooltip="Comma-separated. 'h2,http/1.1' = HTTP/2 with HTTP/1.1 fallback. Empty = HTTP/1.1 only."
                                >
                                  <Input placeholder="h2,http/1.1" />
                                </Form.Item>
                                <Form.Item
                                  name={['ssl', 'ssl_ciphers']}
                                  label="Ciphers (TLSv1.2 and earlier)"
                                  tooltip="OpenSSL cipher list, e.g. ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM"
                                >
                                  <Input placeholder="(use HAProxy default)" />
                                </Form.Item>
                                <Form.Item
                                  name={['ssl', 'ssl_ciphersuites']}
                                  label="Ciphersuites (TLSv1.3)"
                                  tooltip="TLS 1.3 ciphersuites, e.g. TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
                                >
                                  <Input placeholder="(use HAProxy default)" />
                                </Form.Item>
                                {/* R17 minimum-parity: mTLS client cert auth.
                                    Default is (disabled) because 'required'
                                    would lock out every browser that doesn't
                                    ship a client cert. */}
                                {/* Bulgu #26 (round-12 audit): the renderer's
                                    client-CA bundle path resolver
                                    (`_resolve_frontend_client_ca_path`) is a
                                    PR-7 placeholder that always returns None,
                                    so `verify required|optional` is SILENTLY
                                    dropped to avoid a fatal HAProxy ALERT.
                                    Operators who picked "required" got a row
                                    with ssl_verify='required' in the DB but
                                    the actually-deployed bind line had no
                                    `verify` token — mTLS was silently
                                    disabled. Until the ca-file column lands
                                    we restrict the UI to 'none' to match the
                                    backend SSLChoice validator's rejection
                                    of 'optional' / 'required'. */}
                                <Form.Item
                                  name={['ssl', 'ssl_verify']}
                                  label="Client cert verification (mTLS)"
                                  tooltip="Mutual TLS requires a client-CA bundle field which is not yet exposed by the wizard. Pick 'none' or leave blank; configure mTLS via Frontend Management → Advanced TLS once the ca-file UI lands."
                                >
                                  <Select allowClear placeholder="(disabled — anonymous TLS)">
                                    <Option value="none">none — disabled</Option>
                                  </Select>
                                </Form.Item>
                              </>
                            ),
                          }]}
                        />
                      </>
                    ),
                  }]}
                />
              );
            }}
          </Form.Item>
        </>
      ),
    },
    {
      title: 'Review & Apply',
      content: (
        <>
          {/* Bulgu #44: ssl.mode='acme' forces apply_immediately=true (backend
              enforces it via M22). Reflect that in the UI so the switch state
              is never out of sync with the actual submitted value. */}
          {/* R18c round 10 (M8): the coercion now lives in a useEffect at
              the top of this component (search for "M8" there). The Form.Item
              shouldUpdate wrapper is preserved so the Switch re-renders when
              `apply_immediately` flips, but the render function no longer
              schedules a setTimeout setState — that was a setState-in-render
              anti-pattern. */}
          <Form.Item shouldUpdate>
            {() => {
              const currentSslMode = form.getFieldValue(['ssl', 'mode']);
              const acmeForcesApply = currentSslMode === 'acme';
              return (
                <Form.Item name="apply_immediately" label="Apply Immediately" valuePropName="checked">
                  <Switch disabled={acmeForcesApply} />
                </Form.Item>
              );
            }}
          </Form.Item>
          {sslMode === 'acme' && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
              message="Apply Immediately is forced ON for ACME mode (the agent must confirm the new HTTP frontend before Let's Encrypt can validate the HTTP-01 challenge)."
            />
          )}
          <div style={{ marginTop: 16 }}>
            <Button icon={<ReloadOutlined />} onClick={runPreview} loading={previewLoading}>
              Generate diff preview
            </Button>
          </div>
          {previewResults && (
            <div style={{ marginTop: 16 }}>
              {/* Bulgu #36 (round-15 audit) — surface blocking errors as
                  a red banner so the user knows Create will be rejected
                  before they click it. The same strings appear in the
                  warning list below for backward compatibility, but the
                  red banner is the authoritative gate. */}
              {Array.isArray(previewResults.blocking_errors) && previewResults.blocking_errors.length > 0 && (
                <Alert
                  type="error"
                  showIcon
                  message={`Submit will be rejected (${previewResults.blocking_errors.length} blocker${previewResults.blocking_errors.length === 1 ? '' : 's'})`}
                  description={
                    <ul style={{ marginBottom: 0 }}>
                      {previewResults.blocking_errors.map((e, i) => <li key={i}>{e}</li>)}
                    </ul>
                  }
                  style={{ marginBottom: 12 }}
                />
              )}
              {previewResults.warnings?.length > 0 && (
                <Alert
                  type="warning"
                  showIcon
                  message="Warnings"
                  description={
                    <ul>{previewResults.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
                  }
                />
              )}
              <Card size="small" title="Will create" style={{ marginTop: 12 }}>
                <pre style={{ fontSize: 12, whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(previewResults.would_create, null, 2)}
                </pre>
              </Card>
            </div>
          )}
          {/* Phase K Phase C: HAProxy dry-run validation card. */}
          <div style={{ marginTop: 16 }}>
            {dryRunResult.status === 'idle' && (
              <Alert
                type="info"
                showIcon
                message="Preparing HAProxy validation…"
              />
            )}
            {dryRunResult.status === 'loading' && (
              <Alert
                type="info"
                showIcon
                icon={<Spin size="small" />}
                message="Validating against HAProxy…"
                description="Synthesising the candidate config and running the heuristic validator before you click Create."
              />
            )}
            {dryRunResult.status === 'clean' && (
              <Alert
                type="success"
                showIcon
                message="All HAProxy validation checks passed"
                description="The candidate configuration is structurally valid. The agent's haproxy -c -f remains the ultimate gate at apply time."
              />
            )}
            {dryRunResult.status === 'warnings_only' && (
              <Alert
                type="warning"
                showIcon
                message={`Configuration is valid but emitted ${dryRunResult.warnings.length} warning(s)`}
                description={
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {dryRunResult.warnings.map((w, i) => (
                      <li key={i}>
                        {w.section ? `[${w.section}] ` : ''}{w.message}
                        {w.directive ? ` (${w.directive})` : ''}
                      </li>
                    ))}
                  </ul>
                }
              />
            )}
            {dryRunResult.status === 'errors' && (
              <Alert
                type="error"
                showIcon
                message={`${dryRunResult.errors.length} HAProxy validation error(s) found`}
                description={
                  <div>
                    <div style={{ marginBottom: 8 }}>
                      Create is disabled until these errors are resolved. Use the Edit-Step buttons to jump back and fix each issue.
                    </div>
                    <ul style={{ margin: 0, paddingLeft: 20 }}>
                      {dryRunResult.errors.map((e, i) => {
                        const targetStep = _directiveToStep(e.directive);
                        return (
                          <li key={i} style={{ marginBottom: 6 }}>
                            <Space size={4} wrap>
                              <span>
                                {e.section ? <strong>[{e.section}] </strong> : null}
                                {e.message}
                                {e.directive ? <em> ({e.directive})</em> : null}
                              </span>
                              {targetStep !== null && (
                                <Button
                                  size="small"
                                  type="link"
                                  onClick={() => setStep(targetStep)}
                                >
                                  Edit Step {targetStep + 1}
                                </Button>
                              )}
                            </Space>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                }
              />
            )}
            {dryRunResult.status === 'pydantic_error' && (
              <Alert
                type="error"
                showIcon
                message={`${dryRunResult.pydanticErrors.length} field-level validation error(s) found`}
                description={
                  <div>
                    <div style={{ marginBottom: 8 }}>
                      The wizard payload itself is invalid. Use the Edit-Step buttons to jump back and re-enter the affected field(s).
                    </div>
                    <ul style={{ margin: 0, paddingLeft: 20 }}>
                      {dryRunResult.pydanticErrors.map((p, i) => {
                        const targetStep = _locPathToStep(p.loc, p.msg);
                        // Phase K Phase C audit-fix #2 round 4: skip the
                        // empty-path strong/colon prefix for SiteCreate-
                        // level model_validator errors. Pydantic v2 raises
                        // those with `loc=()`; FastAPI prepends `'body'`
                        // so the operator-visible loc is `['body']`. After
                        // `slice(1)` that becomes `[]` → `join('.')` →
                        // empty string, which used to render as a stray
                        // `<strong>: </strong>` before the message text.
                        // Now we conditionally render the path prefix
                        // ONLY when there is actually a field path.
                        const fieldPath =
                          Array.isArray(p.loc) && p.loc.length > 1
                            ? p.loc.slice(1).join('.')
                            : '';
                        return (
                          <li key={i} style={{ marginBottom: 6 }}>
                            <Space size={4} wrap>
                              <span>
                                {fieldPath && (
                                  <strong>{fieldPath}: </strong>
                                )}
                                {p.msg}
                              </span>
                              {targetStep !== null && (
                                <Button
                                  size="small"
                                  type="link"
                                  onClick={() => setStep(targetStep)}
                                >
                                  Edit Step {targetStep + 1}
                                </Button>
                              )}
                            </Space>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                }
              />
            )}
            {dryRunResult.status === 'unavailable' && (
              <Alert
                type="warning"
                showIcon
                message="HAProxy validation could not be performed at this time"
                description={
                  dryRunResult.message ||
                  "The agent's haproxy -c remains the final authority on apply. You can still proceed to Create."
                }
              />
            )}
          </div>
        </>
      ),
    },
  ];

  // R15 hotfix: sslMode moved to the top of the component (above
  // stepContents). Don't redeclare it here. acmeBlocksDraft was
  // removed in Phase K Phase D when the "Create as PENDING" button
  // was retired.

  // Bulgu #6 fix: block ACME submit when pre-flight checks reported a hard
  // failure. Operators can still bypass via the "Continue anyway" checkbox
  // (e.g. egress port-80 false-positive in corp networks). If pre-flight
  // wasn't run we don't block — backend still enforces apply_immediately+http
  // and the staged ACME order surfaces a structured error if validation fails.
  const acmePreflightHasFail =
    sslMode === 'acme' &&
    Array.isArray(preflightResults?.checks) &&
    preflightResults.checks.some((c) => c.status === 'fail');
  const acmeBlocksSubmit = acmePreflightHasFail && !continueAnyway;
  // R18c round 10 (M2): Submit must wait for the cluster-scoped cert
  // list to finish loading WHEN the wizard is in 'existing' SSL mode
  // — otherwise a resumed draft can race the orphan-cleanup pass and
  // submit a stale ssl_certificate_id that has been deleted in the
  // background (FK 400). This guard fires for resumed AND fresh
  // sessions because a slow network on Step 0 + a fast tab switch to
  // Step 4 hits the same race. Other ssl modes (acme / upload / none)
  // do not touch the existing-cert list, so they are unaffected.
  const certReconciliationPending =
    sslMode === 'existing' && existingCertsLoading;
  // Phase K Phase C: gate Create on the dry-run result. Only the
  // hard-error states block (errors / pydantic_error / loading);
  // warnings_only / clean / unavailable keep Create enabled because
  // (a) the agent's haproxy -c is the ultimate gate, and (b) we
  // explicitly mirror the create_site validator-crash-is-non-fatal
  // posture for `unavailable`.
  const dryRunBlocksSubmit =
    dryRunResult.status === 'errors' ||
    dryRunResult.status === 'pydantic_error' ||
    dryRunResult.status === 'loading';
  const dryRunBlockReason =
    dryRunResult.status === 'errors'
      ? 'HAProxy validation reported errors. Resolve them before creating the site.'
      : dryRunResult.status === 'pydantic_error'
        ? 'Field-level validation errors detected. Use the Edit-Step buttons in the validation card to fix them.'
        : dryRunResult.status === 'loading'
          ? 'Validation is still running — please wait a moment.'
          : '';

  // Bulgu #36 (round-15 audit) — surface preview blocking_errors as a
  // hard submit block so operators see them BEFORE clicking Create
  // instead of getting an opaque 400 from `/api/sites`. The /preview
  // endpoint emits the same actionable strings `create_site` would
  // raise (bind collisions, ACME port-80 reachability, HTTPS name
  // collisions, …) into `previewResults.blocking_errors`.
  const previewBlockingErrors = Array.isArray(previewResults?.blocking_errors)
    ? previewResults.blocking_errors
    : [];
  const previewBlocksSubmit = previewBlockingErrors.length > 0;
  const previewBlockReason = previewBlocksSubmit
    ? `${previewBlockingErrors.length === 1 ? 'A blocker' : `${previewBlockingErrors.length} blockers`} was detected by the preview that the submit endpoint will hard-reject. Review the red banner above and adjust the wizard before retrying.`
    : '';

  const submitBlockReason = acmeBlocksSubmit
    ? 'ACME pre-flight reported a hard failure. Tick "Continue anyway" on the SSL step to override.'
    : (previewBlocksSubmit
      ? previewBlockReason
      : (certReconciliationPending
        ? 'Reconciling selected certificate against the cluster — please wait.'
        : dryRunBlockReason));
  // Phase K Phase D (Bulgu #6): label for the (now single) submit
  // button — "Create Site" by default; "Create & Apply (ACME)" when
  // the operator picked ACME so they understand why the standard
  // PENDING → Apply Management round-trip is bypassed on this one
  // flow. The semantic is fully driven by `handleSubmit`'s sslMode-
  // derived `effectiveApply`.
  const submitButtonLabel =
    sslMode === 'acme' ? 'Create & Apply (ACME)' : 'Create Site';
  const submitButtonTooltip = sslMode === 'acme'
    ? (submitBlockReason || 'ACME mode forces immediate apply so the agent can satisfy the HTTP-01 challenge.')
    : (submitBlockReason || 'Creates a PENDING version. You will be taken to Apply Management to review and deploy it.');
  return (
    <Card title="New Site (Wizard)" extra={
      <Space>
        <Button onClick={handleCancel}>Cancel</Button>
        <Tooltip title={submitButtonTooltip}>
          <Button
            type="primary"
            icon={<CheckCircleOutlined />}
            onClick={() => handleSubmit()}
            loading={submitting}
            disabled={acmeBlocksSubmit || certReconciliationPending || dryRunBlocksSubmit || previewBlocksSubmit}
          >
            {submitButtonLabel}
          </Button>
        </Tooltip>
      </Space>
    }>
      <Form
        form={form}
        layout="vertical"
        initialValues={initialValues}
        onValuesChange={() => {
          // Phase K Phase C: invalidate the dry-run result on any
          // field edit so the auto-fire useEffect re-runs the next
          // time the operator lands on Step 4 (or immediately, if
          // they edit a Step-4-visible field like Apply
          // Immediately).
          //
          // Audit-fix #3: read latest status via the REF (not the
          // closure-captured state) and ALSO bump
          // `dryRunInvalidationTick` so the auto-fire effect re-
          // runs even though we removed `dryRunResult.status` from
          // its dep array. Without the tick bump the effect would
          // never re-evaluate after the operator toggles Apply
          // Immediately on Step 4 — the very flag whose change
          // operator MOST wants reflected in the validation card.
          if (dryRunStatusRef.current !== 'idle') {
            setDryRunResult({
              status: 'idle',
              errors: [],
              warnings: [],
              infos: [],
              pydanticErrors: [],
              message: '',
            });
            setDryRunInvalidationTick((t) => t + 1);
          }
        }}
      >
        {resumedFromDraft && (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message="Resumed from draft"
            description={pemStrippedOnResume
              ? 'PEM fields (certificate / private key / chain) were stripped on save and must be re-entered before submitting. You are at Review & Apply; use Previous to edit any field.'
              : 'Your previously saved wizard state has been loaded. You are at Review & Apply; use Previous to edit any field.'}
            closable
            onClose={() => setResumedFromDraft(false)}
          />
        )}
        <Steps current={step} items={stepContents.map((s) => ({ title: s.title }))} style={{ marginBottom: 24 }} />
        {/* Bug B fix: keep ALL step contents mounted at all times. Antd
            Form.Item only registers field values once mounted; rendering
            only the current step caused validateFields() / getFieldsValue()
            to return only the visible step's values — submit fired with
            an empty body ({apply_immediately: true}) and the backend
            returned 422. Hide non-active steps with display:none instead
            of unmounting them so the field registry stays intact. */}
        {stepContents.map((s, idx) => (
          <div
            key={idx}
            style={{ display: step === idx ? 'block' : 'none' }}
            aria-hidden={step !== idx}
          >
            {s.content}
          </div>
        ))}
        <Divider />
        <Space>
          <Button disabled={step === 0} onClick={() => setStep(step - 1)}>Previous</Button>
          <Button
            type="primary"
            disabled={step === stepContents.length - 1}
            onClick={async () => {
              try {
                // R17 fix: per-step validation must walk EVERY required nested
                // path, not just the top-level Form.List wrapper. Antd's
                // validateFields(['servers']) only validates the Form.List
                // metadata — it does NOT trigger the per-row required rules,
                // so users could leave Address blank and `Next` would happily
                // advance, the error surfacing only at submit time.
                if (step === 0) {
                  await form.validateFields(['cluster_id', 'domains']);
                }
                if (step === 1) {
                  const serverRows = form.getFieldValue('servers') || [];
                  const serverPaths = serverRows.flatMap((_, i) => [
                    ['servers', i, 'server_name'],
                    ['servers', i, 'server_address'],
                    ['servers', i, 'server_port'],
                  ]);
                  await form.validateFields([
                    ['backend', 'name'],
                    ...serverPaths,
                  ]);
                }
                if (step === 2) {
                  await form.validateFields([['frontend', 'name']]);
                  // Phase K Phase B: hard-block on the two known
                  // mutually-exclusive combinations BEFORE the wizard
                  // advances. Pre-Phase-K both rejections only surfaced
                  // at the final POST as opaque 422 / 422-derived toasts;
                  // operators reached Step 4 only to be punted back.
                  // The Pydantic validators at
                  // `models/site_wizard.py::reject_redirect_conflict` and
                  // `models/site_wizard.py::reject_tcp_mode_with_https_redirect`
                  // (Phase A) stay as the source of truth — these UI
                  // gates just surface the same logic earlier with a
                  // one-click resolution path.
                  const httpsRedirectNow = form.getFieldValue(['frontend', 'https_redirect']);
                  const frontendModeNow = form.getFieldValue(['frontend', 'mode']);
                  if (httpsRedirectNow && (aclBuilderData.redirectRules || []).length > 0) {
                    message.error(
                      'HTTP→HTTPS redirect cannot be combined with custom redirect rules. ' +
                      'Use the buttons in the alert above to either disable the switch or remove the rules before continuing.'
                    );
                    return;
                  }
                  if (frontendModeNow === 'tcp' && httpsRedirectNow) {
                    message.error(
                      'HTTP→HTTPS redirect requires HTTP mode (L7). TCP frontends operate at L4 ' +
                      'and cannot inspect HTTP headers. Disable the redirect switch or change the ' +
                      'frontend mode to http before continuing.'
                    );
                    return;
                  }
                  // Phase K Phase D follow-up (Bulgu #12 round 3) —
                  // hard-gate the Step 2 → Step 3 advance on any ACL
                  // rule that carries the unsupported `-f <file>`
                  // pattern-file flag. The Pydantic validator rejects
                  // the same shape at submit, but blocking the Next
                  // button here surfaces the error immediately at
                  // its source step (the ACL builder is right above)
                  // instead of bouncing the operator from Step 4's
                  // dry-run card back to Step 2 with a less-specific
                  // jumpback button. The ACLRuleBuilder ALSO renders
                  // a section-level red Alert when this state is
                  // active so the operator already sees what to fix.
                  const FILE_FLAG_RE = /(?:^|\s)-f(?:\s|$)/;
                  const aclRulesAll = [
                    ...(aclBuilderData.aclRules || []),
                    ...(aclBuilderData.useBackendRules || []),
                    ...(aclBuilderData.redirectRules || []).map(
                      (r) => (typeof r === 'string' ? r : ''),
                    ),
                  ];
                  if (aclRulesAll.some((r) => typeof r === 'string' && FILE_FLAG_RE.test(r))) {
                    message.error(
                      'One or more rules use the unsupported HAProxy `-f <file>` ' +
                      'pattern-file flag. HAProxy OpenManager does not provision ' +
                      'pattern files onto the HAProxy node filesystem, so the ' +
                      'reference would fail at reload time. Remove the `-f` flag ' +
                      'and use inline values instead before continuing.'
                    );
                    return;
                  }
                  // Phase K Phase D follow-up (Bulgu #13) — block
                  // advance when any routing / redirect rule has a
                  // self-contradictory condition (`acl1 !acl1`).
                  // HAProxy accepts the syntax but the rule never
                  // fires → silent fallback to `default_backend`.
                  // The ACLRuleBuilder also renders a section-level
                  // Alert and a per-card error decoration; this is
                  // the hard gate that prevents Next when the
                  // operator ignores the inline warning.
                  const CONTRA_TOKEN_RE = /^!?[A-Za-z_][\w.-]*$/;
                  const hasContradiction = (str) => {
                    if (typeof str !== 'string') return false;
                    const pos = new Set();
                    const neg = new Set();
                    for (const raw of str.split(/\s+/)) {
                      if (!raw || raw === 'if' || raw === 'unless') continue;
                      if (!CONTRA_TOKEN_RE.test(raw)) continue;
                      if (raw.startsWith('!')) {
                        neg.add(raw.slice(1));
                      } else {
                        pos.add(raw);
                      }
                    }
                    for (const n of pos) if (neg.has(n)) return true;
                    return false;
                  };
                  const routingAndRedirect = [
                    ...(aclBuilderData.useBackendRules || []),
                    ...(aclBuilderData.redirectRules || []).map(
                      (r) => (typeof r === 'string' ? r : ''),
                    ),
                  ];
                  if (routingAndRedirect.some(hasContradiction)) {
                    message.error(
                      'One or more routing / redirect rules contain the same ACL ' +
                      'in both positive AND negated form (e.g. `if acl1 !acl1`). ' +
                      'HAProxy accepts this syntax but the predicate `X AND NOT X` ' +
                      'is always false, so the rule never fires and traffic ' +
                      'silently falls through to `default_backend`. Remove one of ' +
                      'the two tokens before continuing.'
                    );
                    return;
                  }
                }
                if (step === 3) {
                  // SSL step: only validate the conditional required fields
                  // for the chosen mode. Pydantic enforces the same rules at
                  // submit, but catching them here keeps the user inside the
                  // SSL step instead of bouncing back from Review.
                  const mode = form.getFieldValue(['ssl', 'mode']);
                  if (mode === 'upload') {
                    await form.validateFields([
                      ['ssl', 'name'],
                      ['ssl', 'certificate_content'],
                      ['ssl', 'private_key_content'],
                    ]);
                  } else if (mode === 'existing') {
                    await form.validateFields([['ssl', 'ssl_certificate_id']]);
                  }
                }
                setStep(step + 1);
              } catch (_e) {
                message.error('Please fix validation errors before continuing');
              }
            }}
          >
            Next
          </Button>
          <Button onClick={handleSaveDraft} icon={<SaveOutlined />}>Save Draft</Button>
        </Space>
      </Form>
    </Card>
  );
};

export default SiteWizard;
