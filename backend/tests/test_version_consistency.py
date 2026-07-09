"""v1.8.7: app version is single-source and cannot silently drift.

The UI shows the version via GET /api/version, which returns main.py's `_version_info`. That MUST be
sourced from the one canonical file backend/version.json (co-located with main.py so `COPY . .`
bakes it into every image, regardless of pipeline). main.py's in-code fallback must NOT be a real
version, otherwise it drifts when version.json is bumped but the constant is forgotten — exactly
what left the UI reporting 1.8.4 after 1.8.5/1.8.6 shipped. These checks fail loudly on regression.
"""
import ast
import json
import os
import re

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # backend/
_VERSION_JSON = os.path.join(_BACKEND, "version.json")
_MAIN = os.path.join(_BACKEND, "main.py")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def test_canonical_version_file_exists_and_valid():
    assert os.path.exists(_VERSION_JSON), "backend/version.json (single source of truth) is missing"
    with open(_VERSION_JSON) as f:
        data = json.load(f)
    assert _SEMVER.match(data.get("version", "")), \
        f"backend/version.json version is not semver: {data.get('version')!r}"
    assert data.get("releaseName"), "backend/version.json must have a releaseName"


def _main_fallback_version_info():
    """The literal dict assigned to _version_info in main.py (the in-code fallback)."""
    with open(_MAIN) as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "_version_info":
                    return ast.literal_eval(node.value)
    return None


def test_main_has_no_hardcoded_real_version():
    fb = _main_fallback_version_info()
    assert fb is not None, "could not find the _version_info fallback literal in main.py"
    # Must be a neutral marker, never a real version that can drift out of sync.
    assert not _SEMVER.match(str(fb.get("version", ""))), (
        f"main.py hardcodes a real version {fb.get('version')!r}; it must be a neutral marker "
        f"(e.g. 'unknown') so the version stays single-source in backend/version.json"
    )


def test_main_loads_the_canonical_file_first():
    # The first candidate path main.py reads must resolve to the co-located backend/version.json,
    # so the correct version is available in every image (not dependent on CI staging).
    with open(_MAIN) as f:
        src = f.read()
    assert 'os.path.dirname(__file__), "version.json"' in src, \
        "main.py must read version.json co-located with the module (backend/version.json)"


def test_frontend_package_json_matches_when_present():
    # Only meaningful in a full-repo checkout; the backend image build context (./backend) has no frontend/.
    pkg = os.path.join(os.path.dirname(_BACKEND), "frontend", "package.json")
    if not os.path.exists(pkg):
        pytest.skip("frontend/package.json not in this context (e.g. backend-only image build)")
    with open(_VERSION_JSON) as f:
        canonical = json.load(f)["version"]
    with open(pkg) as f:
        fe = json.load(f)["version"]
    assert fe == canonical, f"frontend/package.json {fe!r} != backend/version.json {canonical!r}"
