# Upgrade Notes — v1.10.14 (a converged node keeps acknowledging)

**Agent-script change, no schema change.** No `SCHEMA_VERSION` bump. After deploying, sync the
Linux agent script from **Agent Management** and let the agents upgrade, or the fix does not
reach the nodes.

- **Symptom:** a VIP shows `SYNCING (0/n)` with an empty *Last ack* even though every member node
  has the rendered `keepalived.conf` on disk, keepalived is running and the VIP is held.
- **Cause:** the deploy report was sent only when the agent actually wrote the config. Once the
  node matched, it took the idempotency early return every cycle and never reported again, so any
  report lost in transit was never retried and the server's view stayed stale permanently.
- **Fix:** the agent re-asserts its state on the idempotent path as well. One request per node
  per poll cycle (~2.5 min); nothing is written and keepalived is not reloaded.
- **Recovery is automatic.** A VIP stuck at SYNCING converges on the first poll after the agents
  pick up the new script. No action on the nodes, no re-apply, no edit to force a rewrite.
- **This is not new in 1.10.12.** The gap dates from the original HA/VIP work; it only became
  visible when acknowledgements were dropped for an unrelated reason.

**Rollback:** safe. Reverting restores the previous behaviour, in which a lost acknowledgement is
never recovered.

---

# Upgrade Notes — v1.10.13 (deploy acknowledgements were dropped)

**Backend only, no schema change.** No `SCHEMA_VERSION` bump, no agent change. If you deployed
v1.10.12, deploy this one too.

- **Regression in v1.10.12.** The takeover-retirement clause added to the keepalived status
  endpoint reused a query placeholder for both an assignment and a comparison. PostgreSQL types a
  placeholder per use, so it was deduced as `text` in one place and `character varying` in the
  other, and asyncpg refused the statement outright.
- **Symptom:** a VIP stayed at `SYNCING (0/n)` with an empty *Last ack* even though the agent log
  showed `applied config for VIP <id>` on every member. Teardown acknowledgements were lost the
  same way, so a deletion never showed as complete.
- **Nothing was damaged.** The failure was on the write of the acknowledgement, not on the node.
  Configs were deployed correctly throughout; only the reporting was lost. Existing VIPs converge
  on the next poll once this is deployed, with no action on the nodes.
- **Verified against a real PostgreSQL**, not by inspection: both statements execute, a matching
  hash retires the takeover authorisation, a non-matching hash and a NULL `applied_config_hash`
  leave it in place, and the acknowledgement is recorded in every case.

**Rollback:** do not roll back to v1.10.12; roll back to v1.10.11 instead, which predates the
clause entirely.

---

# Upgrade Notes — v1.10.12 (valid config rejected by its own warning)

**Agent-script change, no schema change.** No `SCHEMA_VERSION` bump. After deploying, sync the
Linux agent script from **Agent Management** and let the agents upgrade, or the fix does not
reach the nodes.

- **Symptom:** applying a VIP left it stuck at `SYNCING`, the node kept its previous config and
  the agent logged only `config validation failed (keepalived -t)`.
- **Cause:** the agent treated any non-zero exit from `keepalived -t` as invalid. keepalived's
  config-test exit code does not separate fatal from benign: on 2.2.8 a clean config exits 0,
  while `Truncating auth_pass to 8 characters` exits 5 and so do a missing `}` and an unknown
  keyword. A VRRP password longer than eight characters was enough to block every apply, even on
  a node whose own running config emits the same warning.
- **Fix:** the gate judges the output instead. Known-benign messages are dropped and anything
  left still fails, so it fails closed. Verified against real keepalived: the truncation warning
  passes; a missing brace, an unknown keyword and a `SECURITY VIOLATION` are refused.
- **Also:** the agent now reports what keepalived actually said, in its log and in the status the
  HA/VIP page shows. The refusal was correct but unactionable without reproducing it by hand.
- **The fail-safe itself is unchanged:** a config that genuinely fails validation is never
  written and keepalived is never restarted.

**Rollback:** safe. Reverting restores the stricter gate, which rejects valid configs whose
password exceeds eight characters.

---

# Upgrade Notes — v1.10.11 (Adoptable tag names the real blocker)

**Frontend only, no schema change.** No `SCHEMA_VERSION` bump, no API change, no agent change.

- The *Adoptable* tag and the disabled *Adopt* button were derived separately, so they could
  name different problems. A pair blocked by a peer whose config could not be parsed showed
  **MASTER missing**, because the unreadable node's `state MASTER` had not been counted — true,
  but it sent the operator to the wrong node. Both now come from one ordered decision.
- New label **blocked by peer** for a group held up by a node that references the same address
  but cannot be taken over with it. Two MASTERs is now distinct from none.
- Display only. The endpoint's checks and refusals are unchanged.

**Rollback:** safe; purely presentational.

---

# Upgrade Notes — v1.10.10 (Adoption blockers listed once per instance)

**Frontend only, no schema change.** No `SCHEMA_VERSION` bump, no API change, no agent change.

- The adoption panel merged every member's blocker list, so a two-node pair showed each shared
  problem twice. The two files report different line numbers for the same directive, so exact
  de-duplication did not collapse them. Blockers are now merged on the message with the leading
  `line N:` ignored.
- Display only. The endpoint already evaluated the combined set across all nodes, and what it
  accepts or refuses is unchanged.

**Rollback:** safe; purely presentational.

---

# Upgrade Notes — v1.10.9 (Adoption refuses to strand a node)

**Backend + frontend, no schema change.** No `SCHEMA_VERSION` bump, so the built-in roles are
**not** re-seeded. No agent change.

- **Adoption will not leave a node behind.** v1.10.8 resolved the whole VRRP instance, but only
  from nodes it could parse, that were enabled and that were in the same pool. Anything else fell
  out of the set silently while its peers were rewritten. Adoption now refuses if any reported
  `keepalived.conf` mentions the virtual address and is not among the nodes being taken over, and
  says which node and why.
- **The nodes must agree on the shared fields.** `prefix_length`, unicast/multicast mode, HAProxy
  tracking and the VRRP password live on the VIP and are re-rendered onto every member, so one
  node's value used to be imposed on the rest. A disagreement is now refused with both values
  shown.
- **The takeover authorisation is now retired on acknowledgement.** It is the permission to
  overwrite a `keepalived.conf` that does not carry our marker. It was never cleared, so it stayed
  valid for that exact file content indefinitely; restoring the pre-adoption file would have been
  overwritten again without fresh approval. It is now dropped once the member acks our rendered
  config, gated on the acked hash matching `applied_config_hash` so a failed deploy cannot strand
  the VIP.
- **Nothing to do on upgrade.** Existing adopted VIPs keep working; their authorisation is retired
  on the next successful acknowledgement.

**Rollback:** safe. No schema or data migration; reverting restores the previous (more permissive)
adoption checks.

---

# Upgrade Notes — v1.10.8 (VIP adoption takes the whole VRRP instance)

**Backend + frontend, no schema change.** No `SCHEMA_VERSION` bump, so the built-in roles are
**not** re-seeded. No agent impact: nothing about what the agent reports or how it takes a
config over changes.

- **Adoption is now per VRRP instance, not per node.** Every node in the pool reporting the same
  `virtual_router_id` and virtual address becomes a member of one VIP, each with the role,
  priority and interface its own `keepalived.conf` declares, and each with its own one-shot
  takeover hash. The panel lists one row per instance.
- **Why this mattered:** single-node adoption could not produce a working pair. The BACKUP alone
  failed apply, the MASTER alone left the peer unmanaged and the peer could not then be adopted
  (VRID collision). On a **unicast** instance it was worse than inconvenient: the render drops
  the unicast block when there are no peers, so the adopted node fell back to multicast while its
  peer stayed unicast and both could hold the address.
- **New refusals, each with the reason in the message:** the group does not have exactly one
  MASTER; the nodes disagree on `advert_int`; a declared unicast peer is not among the nodes being
  adopted; a node is already a member of a live VIP.
- **Apply Management "View Change" now renders the adopt diff correctly.** It did not recognise
  the `adopt` action and fell through to the generic HAProxy diff, which compared the staged
  `keepalived.conf` against the cluster's previous `haproxy.cfg` and showed the whole HAProxy
  config as removed. Alarming, but display-only — nothing was ever applied from that view.
- **Rejecting an adoption is recoverable again.** It used to hide the node from the panel
  permanently. Nothing clears `vip_discoveries.adopted_vip_id`, a VIP is only soft-deleted so the
  column's `ON DELETE SET NULL` never fires, and the agent does not re-report a file whose hash
  has not changed. Adoptability is now derived from whether the linked VIP is still active.
- **If you adopted a VIP on 1.10.4-1.10.7**, check it before applying: it may have only one
  member. Add the peer from the VIP's edit form, or reject the pending adoption and adopt again —
  the node reappears in the panel under this release.

**Rollback:** safe. No schema or data change; reverting restores the previous single-node
adoption behaviour.

---

# Upgrade Notes — v1.10.7 (HA / VIP follows the selected cluster)

**Backend + frontend, no schema change.** No `SCHEMA_VERSION` bump, so the built-in roles are
**not** re-seeded. No agent impact.

- **The HA / VIP page ignored the cluster picker.** Both the VIP table and the *Unmanaged
  keepalived detected* panel queried the whole fleet, so on an install with more than one
  cluster the lists never changed when the selection did. Both now pass `cluster_id`, mapped to
  the cluster's pool the same way `GET /api/vip?cluster_id=` already worked for Apply
  Management.
- **Behaviour change worth knowing:** the VIP table is now scoped to the selected cluster. It
  used to show every VIP in the fleet. If you relied on the fleet-wide view, the API still
  supports it — `GET /api/vip` and `GET /api/vip/discoveries` without `cluster_id` return
  everything, unchanged.
- **API compatibility:** `cluster_id` is optional on both endpoints. Existing integrations that
  do not send it behave exactly as before.

**Rollback:** safe. The change is a query parameter plus the page that sends it; reverting
restores the fleet-wide lists and touches no data.

---

# Upgrade Notes — v1.10.6 (VIP adoption panel was unreachable)

**One backend fix, no schema change.** No `SCHEMA_VERSION` bump, so the built-in roles are
**not** re-seeded. No API-shape change, no frontend change and zero agent impact.

- **v1.10.4's adoption panel never appeared.** `GET /discoveries` was declared after
  `GET /{vip_id}` in `routers/vip.py`. FastAPI matches routes in declaration order, so the
  discovery list was routed into the get-one-VIP handler, which declares `vip_id: int` and
  answered **422** before the real handler ran. The HA/VIP page treats any non-OK response as
  "nothing to show", so the feature was invisible with no error in any log.
- **Nothing was lost.** The agent side always worked: discoveries were reported and stored in
  `vip_discoveries`. Deploy this backend and the rows appear immediately — no agent upgrade, no
  re-sync of the agent script, no re-report needed.
- **If you are upgrading straight from 1.10.3 or earlier**, follow the v1.10.4 notes below as
  well: that release does bump `SCHEMA_VERSION` (10 → 11), which re-seeds the four built-in
  roles, and its agent script has to reach the nodes before discovery starts.
- **Regression guard.** A static source scan now fails the build if any literal API path in any
  router is declared after a parameterised route that would swallow it. The whole router tree is
  clean as of this release.

**Rollback:** safe and immediate. The change is a route declaration order plus a test; reverting
to 1.10.5 restores the previous (broken-panel) behaviour and touches no data.

---

---

# Upgrade Notes — v1.10.5 (HTTP-01 challenge backend on split deployments)

**Bug fixes, no schema change.** No `SCHEMA_VERSION` bump, so the built-in roles are **not**
re-seeded. No API-shape change and zero agent impact.

- **HTTP-01 could fail silently when HAProxy runs on different hosts than the management stack.**
  The rendered config wrote `server _acme_mgmt <mgmt>:8080` from a value that defaults to
  loopback — and HAProxy resolves that address **on the HAProxy node**, so it pointed at the wrong
  box. Every check still reported success. The per-cluster `acme_backend_url` now has a UI field
  (Cluster Management), changing it actually mints a config version, and the value is validated at
  the write boundary.
- **A config-generation failure could be pushed to agents as the cluster's whole `haproxy.cfg`.**
  The generator reported failure by *returning* `# Error ...` instead of raising, and the apply
  path hashed that comment and stored it as an APPLIED version. Both persisting call sites now
  refuse with 422 and leave the running config in force. **This is worth knowing even if you never
  touch ACME**, since any exception in the generator could trigger it.
- **`frontends.mode` is nullable and was interpolated raw**, emitting a literal `mode None` that
  HAProxy rejects — which fails the whole cluster config, not just that frontend. Normalised now.
- **Cluster creation ignored the ACME fields**: a cluster created with ACME switched on came back
  switched off, with no error.
- **`docker-compose.yml` hardcoded `PUBLIC_URL` / `MANAGEMENT_BASE_URL`**, so a value in your
  `.env` or host environment was silently ignored. They are interpolated now, with the previous
  literals as defaults, so behaviour is unchanged unless you actually set them.
- **Diagnostics stop over-reporting health.** The port-80 check now reads the body, so a reverse
  proxy answering 200 with a web page is no longer counted as a working challenge endpoint. Every
  new condition is a **warning, never a failure** — the Site Wizard blocks submit on a failing
  check, so a new failing condition would have locked installs on upgrade day.
- **Rollback:** downgrade freely. No schema or data change.

---

---

# Upgrade Notes — v1.10.4 (Adopt an existing keepalived VIP)

**Additive, but this release DOES bump the schema — read the role warning below.** Nothing on any
node changes until you adopt a VIP and apply it.

- **Schema:** `SCHEMA_VERSION` bumps to `11`, so on first start the (idempotent) migration
  sequence re-runs once and adds **one new table** (`vip_discoveries`) plus two additive columns
  (`vip_instances.adopted_at`, `vip_members.takeover_expected_hash`). **No existing table is
  altered**, no existing row changes, and the admin password is not reset.
- **⚠️ Built-in roles are re-seeded to their defaults** — the pre-existing behaviour of every
  `SCHEMA_VERSION` bump. If you customised `super_admin` / `operator` / `security_admin` /
  `viewer`, **re-apply those changes after upgrading**. (The three previous releases did not bump
  the version, so this is the first re-seed since v1.9.0.) No new permission strings are
  introduced: discovery and adoption are governed by the existing `vip.read` / `vip.create`.
- **⚠️ The Linux agent script changed, and discovery does not start until nodes run it.** The
  fallback latest Linux agent version moves `2.0.0` → `2.1.0`, so nodes will pull the new script
  through the normal agent-upgrade path. The addition is **read-only**: the agent reads the
  `keepalived.conf` it does not own and reports it, rate-limited to once per content change. It
  writes nothing new to the node. Until a node has upgraded, it simply never appears under
  *Unmanaged keepalived detected*.
- **Nothing is taken over implicitly.** The agent still refuses to overwrite a `keepalived.conf`
  that lacks OpenManager's ownership marker. Adoption authorises exactly **one** takeover of
  exactly the file that was analysed, pinned to its md5: if the file changes between adoption and
  Apply, the agent refuses again and reports `externally_managed` rather than clobbering your
  edit. Re-adopt to pick up the current file.
- **Adoption can refuse, on purpose.** It replaces the file with OpenManager's render, so anything
  the renderer cannot reproduce would be destroyed. Those directives are listed as blockers —
  `notify_*` failover hooks, `vrrp_sync_group`, LVS `virtual_server` sections, a second address in
  one instance, a custom `track_script`, extra `global_defs`. You can accept that loss explicitly
  with a tick, but a value that is *unknown* rather than lost (an absent `virtual_router_id`, or
  an address with no prefix length) cannot be waived — the VRID is fatal to guess and the prefix
  has to be supplied, because picking a netmask for a live VIP would change its routing.
- **Multi-node VIPs need every node.** Adoption covers the node that reported. Its unicast peers
  hold their own `keepalived.conf`, so adopt or add them as members before applying — otherwise
  the render has no peers. The UI says so after a successful adopt.
- **Secrets:** the reported config may contain the VRRP `auth_pass`. It is split at ingest — the
  password is Fernet-encrypted into its own column (same key path as `vip_instances`,
  `VIP_ENCRYPTION_KEY` falling back to a key derived from `SECRET_KEY`) and the stored copy of the
  file has it masked, so nothing readable through the API, the UI preview or a DB dump carries it
  in cleartext.
- **Rollback:** downgrading to 1.10.3 leaves `vip_discoveries` as an unused table and the two new
  columns unread; managed VIPs keep working. One caveat: a VIP adopted on 1.10.4 but **not yet
  applied** loses its takeover authorisation on downgrade, so the node's original config stays in
  place and the VIP sits PENDING — harmless, but re-adopt after upgrading again. Agents already on
  script 2.1.0 keep reporting discoveries to an endpoint that no longer exists; the report fails
  quietly and nothing on the node is affected.

---

# Upgrade Notes — v1.10.3 (Multi-account ACME wizard fix)

**Frontend only. Nothing to do on upgrade.** No schema, no `SCHEMA_VERSION` bump, no API change, no
environment variable, zero agent impact. Installations with a single ACME account behave exactly as
before.

- **What was broken:** with **more than one** ACME account registered, the *Request ACME
  Certificate* wizard did not honour the account you selected. Choosing an HTTP-01 account still
  submitted a DNS-01 request, which the API rejected with
  `The selected ACME account has no DNS provider configured for DNS-01.` The *Review* step also
  named the default account rather than the chosen one, so the mismatch was invisible before
  submitting.
- **Default account:** the wizard previously previewed the **oldest** valid account while the
  backend uses the **newest** (`ORDER BY created_at DESC`). If you never picked an account
  explicitly and have several, requests were already going to the newest one — only the preview was
  wrong. The wizard now previews that same account, marks it `(default)`, and sends `account_id`
  explicitly so the two can no longer diverge.
- **Wildcard guard:** the client-side "wildcard requires a DNS-01 account" block silently stopped
  applying on the *Review* step. Requests were still rejected by the backend, so nothing incorrect
  was ever issued — you now get the warning before submitting instead of an error after.
- **No action needed on existing certificates or orders.** Nothing about issuance, renewal or the
  stored accounts changes; only how the wizard resolves which account a new request uses.
- **Rollback:** downgrade freely. This release changes frontend behaviour only.

---

# Upgrade Notes — v1.10.2 (Dark mode fixes on Apply Management)

**Frontend only. Nothing to do on upgrade.** No schema, no `SCHEMA_VERSION` bump, no API change,
no environment variable, zero agent impact. Light mode is byte-identical: every colour swapped in
this release resolves, under the default algorithm, to exactly the literal it replaced
(`colorWarningBg` → `#fffbe6`, `colorSuccessBg` → `#f6ffed`, `colorErrorBg` → `#fff2f0`, …), so
only dark mode changes.

- **Apply Management panels** were painted with light-mode colour literals, so in dark mode the
  "Pending Changes" box rendered as a cream panel with light text on it. Measured contrast was
  **1.03:1** — effectively invisible. It is now **11.50:1**. The same class of bug affected the
  diff rows in *View Change* (2.21:1 and 2.99:1, now 5.49:1 and 4.01:1), the ACME/pending version
  panels, the VIP pending-delete row and the agent-error recommendation box.
- **Static confirm dialogs came up white in dark mode.** In Ant Design 5 the static
  `Modal.confirm` / `message` / `notification` APIs render into their own detached root and never
  see the app's `ConfigProvider`, so they always used the light algorithm. This release registers
  `ConfigProvider.config({ holderRender })` once at the app root, which fixes **every** static
  dialog in the app (12 components use them), not just Apply Management.
- **Rollback:** downgrade freely. This release changes rendering only.

---

# Upgrade Notes — v1.10.1 (CSR private key encrypted at rest)

**Backward compatible.** Nothing to do on upgrade, and nothing changes for existing clusters,
agents or certificates:

- **Schema:** **no `SCHEMA_VERSION` bump and no migration.** The Fernet token replaces the PEM
  inside the *existing* `ssl_csrs.private_key_pem` TEXT column. As in v1.10.0, this means the
  four built-in roles are **not** re-seeded, so any customization of `super_admin` / `operator` /
  `security_admin` / `viewer` survives.
- **Existing pending CSRs keep working.** Rows written before this release hold a raw PEM and are
  still read transparently, so a CSR that is already out for signature can be imported normally
  after the upgrade. There is no data migration and no downtime step. Those rows stay plaintext
  until they are imported (which NULLs the key) — if you want everything encrypted immediately,
  delete and re-create any long-pending CSRs.
- **Scope:** this covers the PENDING CSR key only. It is the one key in the system that sits idle
  for the whole signing window and is never transmitted. `ssl_certificates.private_key_content`
  and the ACME order keys are unchanged, because agents must receive those in plaintext on every
  poll.
- **Optional env:** `CSR_ENCRYPTION_KEY` (see `.env.template`). If unset, the key is derived from
  `SECRET_KEY` via HKDF with its own info string, so it is independent of the VIP, MFA and DNS
  provider keys.
  - **⚠️ Rotating `SECRET_KEY` while `CSR_ENCRYPTION_KEY` is unset makes pending CSR keys
    unrecoverable.** Import then fails with an explicit "delete this CSR and create a new one"
    error rather than a misleading key-mismatch. Set an explicit `CSR_ENCRYPTION_KEY` if you
    rotate `SECRET_KEY`. Certificates already imported are unaffected — their key lives on the
    certificate row.
- **API / UI / agents:** unchanged. No CSR endpoint ever returned the private key before or now,
  and nothing about the CSR tab changes.
- **Rollback:** the application downgrades cleanly — 1.10.0 starts normally against the same
  database and every other feature is unaffected. The one casualty is a CSR **created on 1.10.1
  and still pending**: 1.10.0 has no decrypt step, so it hands the Fernet token straight to the
  key-pairing check. Measured on a real downgrade, the import then fails with
  `HTTP 500 — Could not verify the certificate/key pair: key parse failed (encrypted?)`; it does
  **not** silently pair the wrong key, and it does not corrupt anything. Import or delete CSRs
  created on 1.10.1 before downgrading. Certificates already imported are unaffected, since their
  key lives on the certificate row, and CSRs created before 1.10.1 are plaintext and still work.

---

# Upgrade Notes — v1.10.0 (GoDaddy DNS-01 provider)

**Backward compatible & additive.** Nothing changes unless you select **GoDaddy** as an ACME
account's DNS provider:

- **Schema:** **no `SCHEMA_VERSION` bump.** The GoDaddy credentials (API Key + Secret) are stored
  as two keys inside the *existing* encrypted
  `letsencrypt_account_dns_credentials.credentials_encrypted` blob — no new table, no new column,
  no migration.
- **✅ Built-in roles are NOT re-seeded.** The re-seed warning in the v1.9.0 notes below is
  triggered by a `SCHEMA_VERSION` bump. This release does not bump it, so any customization you
  made to `super_admin` / `operator` / `security_admin` / `viewer` survives untouched.
- **Permissions / API shape:** unchanged. `GET /api/letsencrypt/dns-providers` simply returns one
  extra entry in its `providers` array; every request and response shape is identical, and the
  credential form is rendered from that schema, so there is no frontend behaviour change either.
- **Environment:** no new variable. GoDaddy credentials use the same Fernet-at-rest path as
  Cloudflare (`DNS_PROVIDER_ENCRYPTION_KEY`, falling back to a key derived from `SECRET_KEY`).
- **Agents:** zero agent changes. DNS-01 is invisible to agents; an issued certificate follows the
  normal PENDING → Apply Management → agent pull pipeline exactly as before.
- **Using it:** the API Key must be a **Production** key from `developer.godaddy.com/keys` (the
  first key that dashboard issues is an OTE/test key and is rejected), the zone must be in the same
  GoDaddy account, and that account needs at least one registered domain before GoDaddy permits DNS
  API access. A Personal Access Token also works — paste it as the Key and leave the Secret blank.
  Credentials are checked against the GoDaddy API before they are stored, so an invalid, OTE or
  ineligible key fails at save time. Note the check is a **read**: a Personal Access Token that has
  `domains.domain:read` but not `domains.dns:update` saves successfully and only fails at the first
  publish, with a 403 in the order timeline.
- **Rollback:** don't select GoDaddy. Existing Manual and Cloudflare accounts and all HTTP-01
  issuance are untouched. **Downgrading after adopting GoDaddy is not a no-op**: on 1.9.0
  `godaddy` is not a known provider, so any account still set to it degrades to the manual-confirm
  path (in-flight DNS-01 orders wait for a confirmation nobody can give and expire after 48h, and
  renewals stop), and the cleanup sweep marks published TXT records cleaned without removing them.
  Before downgrading, switch affected accounts back to Manual or Cloudflare and let the reconcile
  sweep remove outstanding `_acme-challenge` records first. The stored credential row itself is
  inert — an encrypted blob for an unknown provider.

---

# Upgrade Notes — v1.9.0 (CSR creation)

**Backward compatible & additive.** Upgrading to v1.9.0 changes nothing for existing
clusters/agents until you create a CSR:

- **Schema:** `SCHEMA_VERSION` bumps to `10`, so on first start the (idempotent)
  migration sequence re-runs once and adds **one new table** (`ssl_csrs`) plus its
  indexes. **No existing table is altered**, existing rows are untouched, and the
  **admin password is not reset** (the default-user seeding is guarded by an
  existence check, not an upsert). No new permission strings are introduced — all
  CSR endpoints are governed by the existing `ssl.create` / `ssl.read` /
  `ssl.delete` permissions.
- **⚠️ Built-in roles are re-seeded to their defaults (pre-existing behaviour of
  every `SCHEMA_VERSION` bump — verified in a v1.8.10 → v1.9.0 upgrade drill).**
  Because the version gate re-runs the whole sequence, `update_system_roles_to_enterprise_rbac()`
  issues an unconditional `UPDATE roles SET … permissions = <defaults> WHERE name = …`
  for the four **built-in** roles (`super_admin`, `operator`, `security_admin`,
  `viewer`). **Any customization you made to a built-in role is reverted.** In the
  drill, an `operator` role that had been narrowed by removing `apply.execute` and
  `config.bulk_import` came back with both restored (57 → 59 permissions).
  - **Roles you created yourself are NOT affected** — the re-seed matches on the four
    built-in names only.
  - This is not new in v1.9.0: it happens on every release that bumps
    `SCHEMA_VERSION` (v1.7.0, v1.8.0, v1.8.8 …). It is documented as intentional at
    `backend/database/migrations.py` (the "BUMP THIS … OR seeded/role data" note) —
    the migration is treated as the authority on built-in-role contents.
  - **If you have hardened a built-in role, do this:** export it before upgrading
    (`GET /api/roles`), then re-apply your changes after the first start
    (`PUT /api/roles/{id}`) — or, preferably, move your customization into a
    purpose-made custom role, which survives every upgrade.
- **Key storage:** CSR private keys are stored in the database like every other key
  in the system (`ssl_certificates.private_key_content` and the ACME order keys).
  The key is never returned by any CSR API endpoint, and after a successful import
  the CSR row's key copy is set to NULL (the key then lives only on the certificate
  row).
- **Agents:** zero agent changes. Agents never read the new table; a CSR becomes
  visible to agents only after its signed certificate is imported **and** applied via
  Apply Management (the standard PENDING pipeline).
- **Rollback:** simply don't use the CSR tab. The `ssl_csrs` table is inert when
  empty; downgrading the application leaves it as an ignored extra table.

---

# Upgrade Notes — v1.7.0 (HA / VIP Keepalived management, Issue #27)

**Backward compatible & opt-in.** Upgrading to v1.7.0 changes nothing for existing
clusters/agents until you create a VIP:

- **Schema:** `SCHEMA_VERSION` bumps to `3`, so on first start the (idempotent)
  migration sequence re-runs once and adds two **new** tables (`vip_instances`,
  `vip_members`) plus an additive `vip_instances.applied_snapshot` column (enables
  rejecting a pending VIP change and restoring the previous applied state). No existing
  table is altered. Existing rows and the **admin password
  are not reset** (default users are create-if-missing). The only data effect is that
  the **four built-in system roles** (`super_admin`/`operator`/`security_admin`/`viewer`)
  are re-seeded to their canonical permission sets **plus** the new `vip.*` permissions —
  this is the long-standing behavior of the role seeder; **custom roles are untouched**.
- **Agents:** the agent script gains an opt-in keepalived deploy that is a **no-op** on
  any node without an applied VIP, and it **never overwrites a hand-managed
  `/etc/keepalived/keepalived.conf`** (it reports "externally managed" instead).
- **Scope:** VRRP VIPs target bare-metal / VMware / on-prem L2 networks. On AWS/Azure/GCP
  the cloud fabric doesn't honor VRRP/gratuitous-ARP; the UI surfaces this. Ensure host
  firewalls permit VRRP (IP protocol 112).
- **Optional env:** `VIP_ENCRYPTION_KEY` (see `.env.template`) — if unset, the VRRP secret
  encryption key is derived from `SECRET_KEY` (like MFA).

No rollback steps are required to *disable* the feature: simply don't create VIPs (or
delete them — agents tear down their managed keepalived on the next poll).

---

# Agent Upgrade Guide - Dashboard Stats Fix

## Problem
Dashboard showing 0 metrics after agent auto-upgrade due to missing environment variables (`SOCAT_BIN`, `STATS_SOCKET_PATH`) when agent restarts in daemon mode.

## Solution
Implemented **lazy initialization** in both `get_haproxy_stats_csv()` and `get_server_statuses()` functions. These functions now initialize their dependencies on first call, making them completely independent of global variable initialization.

## Deployment Steps

### Step 1: Wait for Pipeline ⏳
```bash
# Pipeline is currently running after git push
# Check status: https://[your-azure-devops]/pipeline
# Wait for deployment to complete (~3-5 minutes)
```

### Step 2: Verify Backend Deployment ✅
```bash
# Check backend logs for successful deployment
kubectl logs -f deployment/backend -n haproxy-manager | head -20

# Expected: New pod started with latest code
```

### Step 3: Update Agent Version in UI 🔄

**Option A: Automatic Script Sync (Recommended)**
```bash
# Get admin token
TOKEN=$(curl -k -s -X POST "https://haproxy-manager.example.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | jq -r '.access_token')

# Sync scripts from files to database (creates version 1.0.0)
curl -k -X POST "https://haproxy-manager.example.com/api/agents/sync-scripts-from-files" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Expected: {"status": "success", "synced": ["linux", "macos"]}
```

**Option B: Manual UI Update**
1. Go to **Agent Management** page
2. Click **Settings** → **Agent Versions**
3. For **Linux** platform:
   - Click **Edit Script**
   - Version: Keep current or increment (e.g., 1.0.3)
   - Changelog: Add "Fixed stats collection after upgrade"
   - Click **Save** (this syncs file content to database)
4. Repeat for **macOS** platform

### Step 4: Upgrade Agents 🚀

**Option A: UI (Single Agent)**
1. Go to **Agent Management** page
2. Select agent (e.g., `demo-agent`)
3. Click **Upgrade** button
4. Wait 30 seconds for agent to restart

**Option B: API (Batch Upgrade)**
```bash
# Get all agents
curl -k -s -X GET "https://haproxy-manager.example.com/api/agents" \
  -H "Authorization: Bearer $TOKEN" | jq '.agents[] | {id, name, version}'

# Upgrade specific agent (replace {agent_id})
curl -k -X POST "https://haproxy-manager.example.com/api/agents/{agent_id}/upgrade" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Step 5: Verify Stats Collection 📊

**Backend Logs** (30 seconds after upgrade):
```bash
kubectl logs -f deployment/backend -n haproxy-manager | grep -E "haproxy_stats_csv|demo-agent"

# Expected logs:
# ✅ "Has haproxy_stats_csv: True"
# ✅ "CSV preview: IyBweG..." (base64 data)
# ✅ "STATS: Parsed 15 rows for cluster demo-cluster1"
```

**Agent Logs** (on agent server):
```bash
sudo tail -f /var/log/haproxy-agent/agent.log | grep STATS

# Expected logs:
# ✅ "STATS: Initialized socat: /usr/bin/socat"
# ✅ "STATS: Using default socket path: /var/run/haproxy/admin.sock"
# ✅ "STATS: Fetched CSV: 2121 bytes, 9 lines, base64: 2828 chars"
```

**Dashboard UI**:
1. Open **Dashboard** page
2. Refresh page (F5)
3. Check metrics:
   - ✅ Frontend/Backend filters populated
   - ✅ Overview metrics showing real data (not 0)
   - ✅ Charts showing data points
   - ✅ "Waiting for Agent Data" warning gone

## Troubleshooting

### Issue: Backend still shows "Has haproxy_stats_csv: False"

**Cause**: Agent hasn't upgraded yet or using old script version

**Solution**:
```bash
# Check agent version on agent server
grep "AGENT_VERSION" /usr/local/bin/haproxy-agent | head -1

# Force agent restart
sudo systemctl restart haproxy-agent

# Check logs immediately
sudo tail -20 /var/log/haproxy-agent/agent.log
```

### Issue: "STATS: socat not available"

**Cause**: socat not installed

**Solution**:
```bash
# Install socat
sudo yum install -y socat  # RHEL/CentOS
sudo apt install -y socat  # Debian/Ubuntu

# Restart agent
sudo systemctl restart haproxy-agent
```

### Issue: "STATS: Socket not found: /var/run/haproxy/admin.sock"

**Cause**: HAProxy stats socket not configured

**Solution**:
```bash
# Check HAProxy config for stats socket
grep "stats socket" /etc/haproxy/haproxy.cfg

# Add if missing (in global section):
# stats socket /var/run/haproxy/admin.sock mode 666 level admin

# Reload HAProxy
sudo systemctl reload haproxy
```

## Verification Checklist

- [ ] Pipeline completed successfully
- [ ] Backend pod restarted with new code
- [ ] Agent scripts synced to database (version visible in UI)
- [ ] Agents upgraded to new version
- [ ] Backend logs show "Has haproxy_stats_csv: True"
- [ ] Agent logs show STATS messages
- [ ] Dashboard showing real metrics
- [ ] Charts populated with data
- [ ] No "Waiting for Agent Data" warning

## Next Upgrades

This fix is **permanent**. Future agent upgrades will NOT break stats collection because:

1. ✅ Functions are self-contained with lazy initialization
2. ✅ No dependency on global variable initialization order
3. ✅ Works in any restart scenario (systemd, daemon mode, upgrade)
4. ✅ Backward compatible with existing agents

**No manual intervention needed for future upgrades!** 🎉

