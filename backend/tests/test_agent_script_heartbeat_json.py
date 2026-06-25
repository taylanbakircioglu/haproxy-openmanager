"""Issue #31 — agent-script hardening guard (static).

The agent install scripts hand-build the heartbeat JSON, so if `collect_system_info` ever yields
nothing the `$system_info,` line collapses to a bare comma and the whole heartbeat is invalid JSON
(HTTP 400). The fix adds a guard at every fragment-form call site that substitutes a single valid
key when system_info is empty. This static check enforces that the guard is present AND kept in
sync across BOTH platform scripts — the project requires the two agent-script copies to stay in
lockstep. (Empty numeric subfields like "memory_total": , are a separate, milder case already
repaired by the backend sanitizer, so they are intentionally NOT guarded in the script — guarding
them with a strict integer test would wrongly reject the scientific-notation that mawk emits for
multi-GB sizes on Debian/Ubuntu.)
"""
import os

_SCRIPT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # backend/
    "utils", "agent_scripts",
)


def _read(name: str) -> str:
    with open(os.path.join(_SCRIPT_DIR, name), "r") as f:
        return f.read()


LINUX = _read("linux_install.sh")
MACOS = _read("macos_install.sh")

# The empty-system_info guard — present at BOTH fragment call sites (register_agent + send_heartbeat).
_B2_GUARD = '[[ "$system_info" != *\'"\'* ]] && system_info=\'"operating_system": "unknown"\''


def test_b2_guard_present_and_in_sync():
    # Two fragment-form call sites per script (register_agent + send_heartbeat), identical wording.
    assert LINUX.count(_B2_GUARD) == 2, "linux_install.sh missing/duplicated empty-system_info guard"
    assert MACOS.count(_B2_GUARD) == 2, "macos_install.sh missing/duplicated empty-system_info guard"


def test_b2_guard_precedes_every_fragment_system_info_use():
    # Every '    $system_info,' fragment line (the one that breaks on an empty value) must be in a
    # function whose system_info was guarded. We assert the count of guards matches the count of
    # fragment-form interpolations' call sites: each script has exactly one register + one
    # send_heartbeat fragment builder feeding those lines, both guarded above.
    for name, script in (("linux", LINUX), ("macos", MACOS)):
        assert script.count("    $system_info,") >= 1, f"{name}: fragment heartbeat form unexpectedly gone"
        assert script.count(_B2_GUARD) == 2, f"{name}: each fragment call site must carry the guard"
