"""
v1.10.8 — the four adoption defects found while testing v1.10.4 on a live HA pair.

B1  The Apply Management "View Change" diff did not recognise the `adopt` action, so the
    version fell through to the generic HAProxy diff and rendered the cluster's whole
    haproxy.cfg as removed.

B2  `vip_discoveries.adopted_vip_id` is write-once and nothing clears it, while a VIP is only
    ever SOFT-deleted — so `ON DELETE SET NULL` never fires. Rejecting an adoption therefore
    hid the node from the panel permanently: the VIP was gone from the VIP list too, and the
    agent does not re-report a file whose hash has not changed. Adoptability is now derived
    from whether the linked VIP is still active.

B3  Adoption took only the node that was clicked. On a two-node pair that meant: adopting the
    BACKUP produced a VIP whose apply fails ("exactly one member must be MASTER"), adopting the
    MASTER left the peer unmanaged, and adopting the peer afterwards hit the VRID-collision
    guard with 409. The pair could never be completed from the panel.

B4  Worst of the four. `render_keepalived_conf` emits the unicast block only when it has peer
    addresses, so a single-member adoption of a UNICAST instance silently dropped it and
    keepalived fell back to multicast on that node while its peer stayed unicast — they stop
    seeing each other and BOTH claim the VIP.

B3 and B4 share one root and one fix: adoption now resolves the whole VRRP instance, keyed on
(virtual_router_id, virtual address) exactly as keepalived groups nodes.

These are source-level and unit tests: the adoption endpoint needs a live database, so the
behaviour that can be exercised without one is pinned here, and the SQL/flow invariants are
pinned by reading the module.
"""
import pathlib
import re

import pytest

BACKEND = pathlib.Path(__file__).resolve().parents[1]
VIP_ROUTER = (BACKEND / "routers" / "vip.py").read_text()
CLUSTER_ROUTER = (BACKEND / "routers" / "cluster.py").read_text()
RENDERER = (BACKEND / "services" / "keepalived_config.py").read_text()


def _adopt_body() -> str:
    start = VIP_ROUTER.index("async def adopt_vip")
    return VIP_ROUTER[start:]


# ----------------------------------------------------------------------------
# B1 — the diff must recognise `adopt`
# ----------------------------------------------------------------------------

def test_view_change_diff_recognises_the_adopt_action():
    match = re.search(r"vip_match = re\.search\(r'vip-\(\\d\+\)-\(([^)]+)\)'", CLUSTER_ROUTER)
    assert match, "the vip version regex moved; re-point this test"
    actions = set(match.group(1).split("|"))
    assert actions == {"create", "update", "delete", "adopt"}, (
        f"the View Change diff recognises {sorted(actions)}. An action missing here does not "
        f"degrade gracefully: the version falls through to the generic HAProxy diff and shows "
        f"the cluster's whole haproxy.cfg as removed."
    )


def test_every_staged_vip_action_is_covered_by_the_diff_regex():
    """Whatever _stage_vip_version can be called with must be in that alternation."""
    staged = set(re.findall(r'_stage_vip_version\(conn, vip_id, "(\w+)"', VIP_ROUTER))
    match = re.search(r"vip_match = re\.search\(r'vip-\(\\d\+\)-\(([^)]+)\)'", CLUSTER_ROUTER)
    recognised = set(match.group(1).split("|"))
    assert staged, "no _stage_vip_version call sites found; re-point this test"
    assert staged <= recognised, (
        f"staged action(s) {sorted(staged - recognised)} are not recognised by the View Change "
        f"diff regex {sorted(recognised)}"
    )


# ----------------------------------------------------------------------------
# B2 — adoptability follows the VIP's liveness, not the bare link
# ----------------------------------------------------------------------------

def test_discovery_api_exposes_whether_the_adopted_vip_still_stands():
    assert "adopted_vip_active" in VIP_ROUTER, (
        "the discovery payload no longer reports whether the adopted VIP is still active; the "
        "UI would go back to hiding a rejected adoption forever"
    )
    assert re.search(r"LEFT JOIN vip_instances av ON av\.id = d\.adopted_vip_id", VIP_ROUTER), (
        "the discovery query must join the linked VIP to report its is_active"
    )


def test_adopt_refuses_only_while_the_previous_adoption_still_stands():
    body = _adopt_body()
    assert re.search(r'if disc\["adopted_vip_id"\] and disc\["adopted_vip_active"\]', body), (
        "adopt must refuse only when the linked VIP is still ACTIVE — refusing on the bare link "
        "makes a rejected adoption impossible to retry, because nothing ever clears the column"
    )


def test_nothing_clears_adopted_vip_id_so_the_derivation_is_load_bearing():
    """If a future change starts clearing the column, this test should be revisited rather than
    silently left in place — the derived flag is what makes reject recoverable today."""
    writes = re.findall(r"UPDATE vip_discoveries SET adopted_vip_id = (\S+)", VIP_ROUTER)
    assert writes, "no adopted_vip_id write found; re-point this test"
    assert all(w != "NULL" for w in writes), (
        "adopted_vip_id is now cleared somewhere — re-check that the adopted_vip_active "
        "derivation and this test still describe reality"
    )


# ----------------------------------------------------------------------------
# B3 — the whole VRRP instance is adopted, not one node
# ----------------------------------------------------------------------------

def test_participants_are_resolved_by_vrid_and_address():
    assert "async def _collect_instance_participants" in VIP_ROUTER
    start = VIP_ROUTER.index("async def _collect_instance_participants")
    end = VIP_ROUTER.index("@router.post(\"/adopt\")", start)
    body = VIP_ROUTER[start:end]
    assert 'v.get("virtual_router_id") == vrid' in body and 'v.get("virtual_ip") == virtual_ip' in body, (
        "instance identity must be (VRID, address) — the same key keepalived uses to decide two "
        "nodes are one VRRP group"
    )
    assert 'if r["parse_error"]' in body, "a node whose config failed to parse must not become a member"
    assert 'r["adopted_vip_id"] and r["adopted_vip_active"]' in body, (
        "a node already held by a STANDING VIP must not be pulled into a second one"
    )


def test_adopt_inserts_one_member_per_participant():
    body = _adopt_body()
    insert = body.index("INSERT INTO vip_members")
    preceding = body[:insert]
    assert "for p in participants:" in preceding, (
        "members must be inserted in a loop over the resolved participants; a single insert is "
        "the half-adoption bug"
    )
    assert 'p["config_hash"]' in body[insert:insert + 800], (
        "each member must carry ITS OWN takeover hash — the one-shot takeover guard is per node"
    )


def test_adopt_requires_exactly_one_master_across_the_instance():
    body = _adopt_body()
    assert 'roles.count("MASTER") != 1' in body, (
        "adoption must reject an instance that does not have exactly one MASTER, instead of "
        "letting apply fail later with 'exactly one member must be MASTER'"
    )


def test_adopt_enforces_one_active_vip_per_agent():
    body = _adopt_body()
    assert "already a member of VIP" in body, (
        "adoption must enforce the one-active-VIP-per-agent rule that create/update enforce via "
        "_validate_members_against_pool; a second membership never converges"
    )


# ----------------------------------------------------------------------------
# B4 — a unicast instance can never be half-adopted
# ----------------------------------------------------------------------------

def test_renderer_only_emits_unicast_when_it_has_peers():
    """The property that makes B4 dangerous. Pinned so the guard below keeps its reason."""
    assert re.search(r"if use_unicast and peer_ips:", RENDERER), (
        "the renderer no longer gates the unicast block on having peers; re-derive whether the "
        "adoption guard is still needed"
    )


def test_adopt_refuses_a_unicast_peer_that_is_not_being_adopted():
    body = _adopt_body()
    assert "declared_peers" in body and "member_ips" in body, (
        "adoption must verify every declared unicast peer is among the nodes being adopted"
    )
    assert "fall back to multicast" in body, (
        "the refusal must explain the consequence — silently dropping a peer puts both nodes in "
        "MASTER state on the same address"
    )


def test_adopt_refuses_to_strand_any_node_that_references_the_address():
    """The half-adoption hole that instance resolution alone does not close.

    Participant resolution can only match a node it can READ, that is ENABLED and that is in the
    SAME pool. Each of those is a door a real member leaves through silently, and the nodes that
    remain get rewritten while it keeps serving the same address unmanaged. Seen for real: one
    node of a pair had a missing closing brace, so it parsed to nothing while its partner parsed
    cleanly. Rather than guard each door, the endpoint asks whether ANY reported config mentions
    this address and is not among the nodes being adopted.
    """
    body = _adopt_body()
    assert "raw_config_masked LIKE" in body, (
        "the check must be scoped to configs that reference THIS virtual address, so an unrelated "
        "file elsewhere in the fleet does not block every adoption"
    )
    assert "NOT (a.id = ANY($2::int[]))" in body, (
        "the guard must catch every node that is NOT a participant, not just the unparseable "
        "ones — a disabled agent and a peer in another pool are stranded exactly the same way"
    )
    assert "COALESCE(av.is_active, FALSE) = FALSE" in body and "d.is_managed = FALSE" in body, (
        "a node already under management is not stranded and must not block adoption"
    )
    for reason in ("could not be parsed", "agent is disabled", "different agent pool"):
        assert reason in body, f"the refusal must be able to explain '{reason}'"


@pytest.mark.parametrize("field,label", [
    ("prefix_length", "prefix length"),
    ("use_unicast", "unicast/multicast mode"),
    ("track_haproxy", "HAProxy tracking"),
])
def test_adopt_requires_agreement_on_shared_vip_fields(field, label):
    """These live on the VIP row and are re-rendered onto EVERY member, so taking them from the
    node that happened to be clicked imposes its settings on the others. prefix_length is the
    sharpest: the design refuses to guess a netmask for a live VIP, and copying one node's
    netmask onto another is that same change by another name."""
    body = _adopt_body()
    assert f'("{field}", "{label}")' in body, (
        f"{field} is written to the VIP row from one node's report; adoption must refuse when the "
        f"nodes disagree about it"
    )


def test_adopt_requires_one_shared_vrrp_password():
    body = _adopt_body()
    assert "decrypt_vrrp_secret(enc)" in body, (
        "Fernet is non-deterministic, so the per-node tokens cannot be compared as ciphertext — "
        "they must be decrypted and compared as plaintext"
    )
    assert "do not share one VRRP password" in body, (
        "adoption stores ONE secret and renders it onto every member, so a mismatch must be "
        "refused rather than silently normalised"
    )
    assert "cannot be decrypted" in body, (
        "a token we cannot decrypt must be an error, not silently treated as equal to another"
    )


def test_adopt_requires_reported_ips_before_trusting_the_peer_check():
    body = _adopt_body()
    assert "have not reported an IP address yet" in body, (
        "the unicast peer check compares against member IPs, so a member without a reported IP "
        "must block the check rather than silently pass it"
    )


# ----------------------------------------------------------------------------
# The takeover authorisation is genuinely one-shot
# ----------------------------------------------------------------------------

def test_takeover_authorisation_is_retired_once_the_node_acks_our_config():
    """`takeover_expected_hash` is the permission to overwrite a keepalived.conf that does NOT
    carry our ownership marker. It was written at adoption and never cleared, so the release
    notes' "authorises exactly ONE takeover" was only true as "for exactly that file content,
    indefinitely" — restoring the pre-adoption file would have been silently overwritten again
    with no fresh human approval."""
    agent_router = (BACKEND / "routers" / "agent.py").read_text()
    assert "takeover_expected_hash = CASE WHEN applied_config_hash IS NOT NULL" in agent_router, (
        "the status ack must retire the takeover authorisation once the node confirms our config"
    )
    assert "ELSE takeover_expected_hash END" in agent_router, (
        "a non-matching ack must LEAVE the authorisation in place — dropping it on a partial or "
        "failed deploy would leave the VIP unable to converge"
    )


def test_validation_judges_the_output_not_the_exit_code():
    """keepalived's config-test exit code cannot separate fatal from benign.

    Measured on keepalived 2.2.8 rather than assumed:

        clean config ..................... 0
        auth_pass longer than 8 chars .... 5   "Truncating auth_pass to 8 characters"
        missing '}' ...................... 5   "There are 1 missing '}'s"
        unknown keyword .................. 5   "Unknown keyword '...'"
        script without script_security ... 6   "SECURITY VIOLATION ..."

    So 5 covers both a harmless truncation and a broken file. Treating any non-zero exit as
    invalid rejected VALID configs: a VRRP password over 8 characters is enough, and keepalived
    truncates it to 8 anyway, exactly as it does for the file the operator already runs. Found
    on the first live adoption, where the node's OWN running config also exited non-zero.

    The gate must therefore judge the output, and it must fail CLOSED: anything not on the
    benign list still counts as fatal.
    """
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    assert script.count("grep -v 'Truncating auth_pass to 8 characters'") == 2, (
        "both daemon copies must drop the known-benign truncation warning before judging"
    )
    assert script.count('if [[ -n "$kp_fatal" ]]; then') == 2, (
        "the decision must be made on what REMAINS after the benign lines are dropped"
    )
    # Fail-closed: the benign list is an allowlist, never a denylist of fatal messages. The
    # measured table above is quoted in a comment inside the script, so assert on what is used
    # as a grep PATTERN rather than on the text appearing anywhere.
    patterns = re.findall(r"grep -v '([^']*)'", script)
    assert set(patterns) == {"Truncating auth_pass to 8 characters", "^[[:space:]]*$"}, (
        f"the validation filter greps for {sorted(set(patterns))}. It must drop only messages "
        f"known to be benign; matching on fatal messages instead would let an unrecognised "
        f"error through."
    )


def test_validation_fails_closed_when_keepalived_says_nothing():
    """A non-zero exit with no output must stay fatal.

    Filtering the output introduces a way to reach the accept path with an EMPTY filter result,
    and some keepalived builds log to syslog rather than stderr — on such a host every config
    would then be accepted regardless of what is wrong with it. Verified against a stub that
    exits non-zero silently, and against one that emits only whitespace.
    """
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    assert script.count('if [[ -z "${kp_out//[[:space:]]/}" ]]; then') == 2, (
        "both daemon copies must treat a non-zero exit with no readable output as fatal"
    )
    assert script.count('kp_fatal="keepalived -t exited non-zero without output"') == 2


def test_validation_failure_reports_what_keepalived_said():
    """The fail-safe protected the node correctly on a live adoption but logged only
    "config validation failed", with keepalived's own output sent to /dev/null. The operator
    had no way to act on it without reproducing the check by hand on the node."""
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    assert 'keepalived -t -f "$tmp_conf" >/dev/null 2>&1' not in script, (
        "keepalived's output must not be discarded — a fail-safe that cannot say why it fired "
        "is only half a safety feature"
    )
    assert script.count('kp_out=$(keepalived -t -f "$tmp_conf" 2>&1)') == 2, (
        "both daemon copies must capture the validation output"
    )
    # The text is interpolated into JSON by both `log` and _kp_report, so it must be sanitised.
    assert script.count(r"""tr -d '"\\'""") == 2, (
        "captured output must have quotes and backslashes stripped before it reaches the JSON "
        "log line and the status report"
    )
    assert script.count('keepalived -t failed: ${kp_err}') == 2, (
        "the reason must also travel to the server so the UI can show it"
    )


def test_converged_node_keeps_acknowledging():
    """The idempotent path must still report, or a lost ack is never recovered.

    The status report is the server's ONLY evidence that a member converged, and it used to be
    sent solely on the write path. Once the rendered config was on disk the agent took the
    idempotency early return every cycle and never spoke again, so a single lost report - a
    backend restart, a 5xx, a network blip - left the VIP reading SYNCING forever with an empty
    "Last ack" while the node was demonstrably running the right config. Seen in the field after
    acks were dropped for an unrelated reason: the node was correct, the page was not, and
    nothing would ever reconcile them.
    """
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    assert script.count('_kp_report "enabled" "$vip_id" "$new_hash" "already converged"') == 2, (
        "both daemon copies must re-assert the deploy state on the idempotent path; without it "
        "the server can never recover a lost acknowledgement"
    )
    # The report has to come BEFORE the early return in both copies.
    for m in re.finditer(r'if \[\[ -n "\$cur_hash" && "\$cur_hash" == "\$would_hash" \]\]; then(.*?)fi',
                         script, re.S):
        body = m.group(1)
        assert body.index("_kp_report") < body.index("return 0"), (
            "the acknowledgement must be sent before returning, or the early return skips it"
        )


def test_status_ack_statements_bind_each_placeholder_once():
    """Every `$n` in the keepalived-status UPDATEs must be used exactly once, and the count must
    match the arguments passed.

    Reusing one placeholder for both the assignment (`last_deploy_hash=$n`, a VARCHAR column)
    and the comparison inside the takeover-retirement CASE made PostgreSQL deduce two types for
    it, and asyncpg rejected the whole statement with AmbiguousParameterError. The failure was
    not partial: no ack was written at all, so every VIP sat at SYNCING forever and teardown acks
    were lost too. Shipped in v1.10.12 and caught in the field.

    The suite has no database, so this pins the shape that made it possible rather than the SQL
    behaviour: one placeholder, one binding site.
    """
    src = (BACKEND / "routers" / "agent.py").read_text()
    start = src.index("async def agent_keepalived_status")
    seg = src[start:src.index('return {"status": "ok"}', start)]

    retire = "".join(re.findall(r'"([^"]*)"',
                                re.search(r"_retire_takeover = \((.*?)\)\n", seg, re.S).group(1)))
    calls = re.findall(r'await conn\.execute\(f"""(.*?)""",\s*(.*?)\)\n', seg, re.S)
    assert len(calls) == 2, f"expected the two ack UPDATEs, found {len(calls)}"

    for sql, args in calls:
        placeholder = re.search(r'_retire_takeover\.format\(p="(\$\d+)"\)', sql).group(1)
        rendered = re.sub(r"\{_retire_takeover\.format\(p=\"\$\d+\"\)\}",
                          retire.replace("{p}", placeholder), sql)
        used = re.findall(r"\$(\d+)", rendered)
        dupes = {n for n in used if used.count(n) > 1}
        assert not dupes, (
            f"placeholder(s) {sorted('$'+d for d in dupes)} are bound more than once. PostgreSQL "
            f"deduces a type per USE, so a placeholder that is both assigned to a column and "
            f"compared against one is ambiguous and the whole UPDATE is rejected."
        )
        n_args = len([a for a in args.split(",") if a.strip()])
        assert max(int(n) for n in used) == n_args, (
            f"the statement uses ${max(int(n) for n in used)} but {n_args} arguments are passed"
        )


def test_takeover_still_requires_the_pinned_hash_to_match_on_disk():
    """The guard that stops an edit between adoption and Apply from being overwritten."""
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    guard = '[[ "$allow_takeover" == "true" && -n "$expected_hash" && "$disk_hash" == "$expected_hash" ]]'
    assert script.count(guard) == 2, (
        f"the takeover guard must be present in BOTH daemon copies (found {script.count(guard)}); "
        f"a self-upgraded agent runs the in-script copy, a freshly installed one the heredoc"
    )


# ----------------------------------------------------------------------------
# Backward compatibility
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("guard", [
    "version_name NOT LIKE 'vip-%'",     # bulk apply/reject still skip VIP versions
])
def test_vip_versions_stay_excluded_from_the_haproxy_apply_flow(guard):
    assert guard in CLUSTER_ROUTER, (
        "vip-* versions must stay out of the HAProxy apply/reject sweep; they are owned by the "
        "VIP endpoints and are never served as haproxy.cfg"
    )


def test_vip_version_transition_matches_any_action():
    """_transition_vip_versions must key on the VIP id alone, or a new action's PENDING row
    would be stranded in Apply Management after apply/reject."""
    assert 'f"vip-{vip_id}-%"' in VIP_ROUTER, (
        "the PENDING -> APPLIED/REJECTED transition must match every action for the VIP"
    )


# ----------------------------------------------------------------------------
# v1.11.1 — a discovery report that was never accepted must be retried
# ----------------------------------------------------------------------------

def test_discovery_is_cached_only_when_the_server_accepted_it():
    """`curl` without -f exits 0 on 500/403/404, so the previous `if curl ...` recorded a
    REJECTED discovery as delivered. The cache then suppressed every later attempt, and since
    the file never changes on its own the node stayed out of the adoption panel permanently:
    the only cure was deleting the cache on the node by hand."""
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    assert "if curl -k -s --connect-timeout 10 --max-time 30 -o /dev/null -X POST" not in script, (
        "the discovery POST must not be judged by curl's exit code; it is 0 for 5xx as well"
    )
    assert script.count('if [[ "$disc_code" =~ ^2[0-9][0-9]$ ]]; then') == 2, (
        "both daemon copies must cache only on a 2xx"
    )


def test_discovery_cache_defers_to_the_server():
    """Recovery without touching the node. The server reports whether it actually holds a
    discovery for this agent; only an explicit `false` overrides the cache, so a backend older
    than v1.11.1 (which omits the field) keeps the previous behaviour instead of being flooded
    with re-posts."""
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    agent_router = (BACKEND / "routers" / "agent.py").read_text()

    assert agent_router.count('AS discovery_known') == 1, (
        "the keepalived-config query must report whether a discovery row exists"
    )
    assert agent_router.count('"discovery_known": bool(agent["discovery_known"])') == 5, (
        "every response path that knows the agent must carry the flag — the adoptable nodes are "
        "precisely the not_configured ones"
    )
    assert script.count('jq -r \'if has("discovery_known")') == 2
    assert script.count('[[ "$disc_known" != "false" ]] && return 0') == 2, (
        "only an explicit false may override the cache, or an older backend — which omits the "
        "field — would cause a re-post on every cycle"
    )
    assert script.count('conf chk disc_known=""') == 2, (
        "disc_known must be function-local; in the in-script daemon the enclosing scope is the "
        "poll loop, so a stale value would outlive the response it came from"
    )


def test_keepalived_config_path_is_resolved_deterministically():
    """A pool may hold more than one cluster, and the join multiplies the agent row. Without an
    ordering the fetch took an arbitrary cluster, so the keepalived.conf PATH handed to the agent
    was non-deterministic whenever two clusters in a pool disagreed on it: the agent would look at
    the wrong file, find nothing, and the node would never appear for adoption."""
    src = (BACKEND / "routers" / "agent.py").read_text()
    start = src.index("async def get_agent_keepalived_config")
    q_start = src.index('agent = await conn.fetchrow("""', start)
    query = src[q_start:src.index('""", agent_name)', q_start)]
    assert "LEFT JOIN haproxy_clusters" in query, "re-point this test; the join moved"
    assert "ORDER BY" in query and "LIMIT 1" in query, (
        "the cluster row must be picked deterministically, or the config path the agent is told "
        "to inspect can change between polls"
    )
    assert "hc.keepalived_config_path = '/etc/keepalived/keepalived.conf'" in query, (
        "the ordering must prefer a CUSTOMISED path over the shipped default. The column defaults "
        "to that path rather than NULL, so ordering by id alone could pick a default-valued row "
        "over one the operator deliberately set, turning 'undefined' into 'reliably wrong'."
    )


def test_daemon_copies_agree_on_the_whole_keepalived_path():
    """Everything the adoption flow depends on must behave identically on BOTH install routes:
    a freshly installed agent runs the heredoc body, a self-upgraded one runs the in-script
    daemon. Comments may differ; logic may not."""
    import difflib
    lines = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text().splitlines()
    term = next(i for i, l in enumerate(lines) if l.strip() == "AGENT_SCRIPT")

    def strip_comment(s):
        out, q, esc = [], None, False
        for ch in s:
            if esc:
                out.append(ch); esc = False; continue
            if ch == "\\":
                out.append(ch); esc = True; continue
            if q:
                out.append(ch)
                if ch == q:
                    q = None
                continue
            if ch in ('"', "'"):
                q = ch; out.append(ch); continue
            if ch == "#":
                break
            out.append(ch)
        return "".join(out).rstrip()

    def funcs(block):
        found = {}
        for idx, l in enumerate(block):
            m = re.match(r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\(\)\s*\{\s*(#.*)?$", l)
            if not m:
                continue
            close = m.group(1) + "}"
            end = next((j for j in range(idx + 1, len(block)) if block[j].rstrip() == close), None)
            if end is None:
                continue
            found[m.group(2)] = [re.sub(r"\s+", " ", strip_comment(x).strip())
                                 for x in block[idx + 1:end] if strip_comment(x).strip()]
        return found

    here, insc = funcs(lines[923:term]), funcs(lines[term + 1:])
    for name in ("_kp_discover", "_kp_report", "_kp_teardown",
                 "fetch_and_deploy_keepalived_config", "get_keepalive_state"):
        assert name in here and name in insc, f"{name} is missing from one daemon copy"
        if here[name] != insc[name]:
            d = "\n".join(x for x in difflib.unified_diff(here[name], insc[name], lineterm="")
                          if x[:1] in "+-" and x[:3] not in ("+++", "---"))
            raise AssertionError(
                f"{name}() differs between the daemon copies, so a self-upgraded agent would "
                f"behave differently from a freshly installed one:\n{d}"
            )


def test_discovery_flag_distinguishes_false_from_absent():
    """jq's `//` returns the alternative for **false** as well as null.

    `.discovery_known // empty` therefore yields an empty string both when the backend omits the
    field (older release) and when it explicitly says `false` (no discovery on record) — the one
    case the recovery exists for. Written that way the fix is inert: the cache is never overridden
    and a stuck node stays hidden. Caught in review, before it shipped, by parsing a real response
    rather than passing the value in by hand.
    """
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    assert "'.discovery_known // empty'" not in script, (
        "jq's // treats false like null, so this cannot tell 'no record' from 'old backend'"
    )
    expected = ('disc_known=$(echo "$resp" | jq -r \'if has("discovery_known") '
                'then (.discovery_known|tostring) else "" end\' 2>/dev/null)')
    assert script.count(expected) == 2, (
        "both daemon copies must distinguish an explicit false from an absent field"
    )


def test_discovery_backs_off_on_a_permanent_rejection():
    """A 4xx means the payload itself is unacceptable, so re-posting the same bytes cannot help.

    Retrying forever is not free here: 4xx and 5xx agent calls are never sampled out of the
    request log (see request_log_sink), so an unattended loop writes a row carrying the whole
    keepalived.conf every poll cycle, on every affected node — the exact "polling noise evicts
    the forensic record" failure the log's own defaults exist to prevent. The cache therefore
    records the rejection and stays quiet until the file changes; a 5xx or a transport failure
    is still retried, which is what the recovery depends on.
    """
    script = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text()
    brake = ('elif [[ "$disc_code" == "400" || "$disc_code" == "413" '
             '|| "$disc_code" == "422" ]]; then')
    assert script.count(brake) == 2, (
        "the brake must be limited to the codes that mean 'these bytes are unacceptable'"
    )
    # 401 and 404 are 4xx but TRANSIENT here: a token rotation, or an agent row briefly absent
    # while it re-registers. Braking on them would silence discovery for every affected node
    # until its keepalived.conf changed, which for a hand-maintained file may be never — the
    # exact failure this release removes.
    for transient in ('"401"', '"404"'):
        assert transient not in brake, (
            f"{transient} must stay in the retry class; it does not mean the payload is bad"
        )
    assert script.count("""printf '%s rejected' "$cur_hash" > "$cache" 2>/dev/null""") == 2
    assert script.count('[[ "$cached_state" == "rejected" ]] && return 0') == 2, (
        "a recorded rejection must suppress the post even when the server reports no record, "
        "or the flag override turns into an unbounded retry loop"
    )
    # The rejection must be keyed to the CONTENT, so a fixed config is retried.
    assert script.count('cached_hash="${cached_line%% *}"') == 2, (
        "the rejection is stored against the hash; changing the file must clear the brake"
    )


def test_config_import_reaches_a_freshly_installed_agent():
    """`check_config_requests` uploads the node's live haproxy.cfg when the operator asks for it.

    It was defined in the installer body and in the in-script daemon, but NOT in the heredoc a
    fresh install writes to /usr/local/bin/haproxy-agent. Its call site is guarded by
    `type check_config_requests`, so on a freshly installed agent the whole feature was a silent
    no-op: the operator requested a config from the node and nothing ever arrived, with no error.
    Agents that had self-upgraded at least once did have it, which is why it went unnoticed.
    """
    lines = (BACKEND / "utils" / "agent_scripts" / "linux_install.sh").read_text().splitlines()
    term = next(i for i, l in enumerate(lines) if l.strip() == "AGENT_SCRIPT")
    pattern = re.compile(r"^\s*check_config_requests\(\)\s*\{")

    in_heredoc = sum(1 for l in lines[923:term] if pattern.match(l))
    in_daemon = sum(1 for l in lines[term + 1:] if pattern.match(l))
    assert in_heredoc == 1, (
        "the heredoc a fresh install writes must define check_config_requests, or Config Import "
        "silently does nothing on any node that has never self-upgraded"
    )
    assert in_daemon == 1, "the self-upgrade daemon must keep its definition"

    # And the two must be the same function, not two drifting implementations.
    def body(block):
        idx = next(i for i, l in enumerate(block) if pattern.match(l))
        out = []
        for l in block[idx:]:
            out.append(l.strip())
            if l.strip() == "}" and len(out) > 5:
                break
        return out

    assert body(lines[923:term]) == body(lines[term + 1:]), (
        "the two copies of check_config_requests have drifted"
    )
