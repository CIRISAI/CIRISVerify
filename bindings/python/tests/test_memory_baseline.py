"""Memory baseline + leak-detection tests for the v1.7 storage_descriptor
and v1.8 build_manifest FFI surfaces.

These tests assert that:

1. The library loads without monstrous RSS overhead.
2. Repeated storage_descriptor() calls don't leak (RSS stabilizes after warmup).
3. Pydantic StorageDescriptor parsing is allocation-bounded.

Run with:
    cd bindings/python
    python -m pytest tests/test_memory_baseline.py -v -s

These tests are SKIPPED if the live FFI library cannot construct a handle
(e.g., on a host with a wedged TPM or missing libtss2-* deps). The tests
that don't need a live handle (pydantic parsing, type construction) still run.
"""

import gc
import json
import os
import tracemalloc

import pytest

from ciris_verify.types import StorageDescriptor, StorageKind, KeyringScope


# Allocation budget for parsing a single descriptor. tracemalloc snapshot
# diff after parsing 1000 descriptors. ~50 bytes per parse on pydantic v2.
ALLOCATION_BUDGET_PER_PARSE_BYTES = 200

# RSS-stability budget after warmup. Any persistent growth larger than
# this across the test loop is treated as a leak.
RSS_STABILITY_BUDGET_KB = 256

# Total RSS budget for the constructor (library load + first init).
# This is generous — actual measurement is closer to 6 MB.
INIT_RSS_BUDGET_MB = 64


def _rss_kb():
    """Return current process RSS in KB (Linux only)."""
    try:
        with open(f"/proc/{os.getpid()}/statm") as f:
            # statm: size resident shared text lib data dt (in pages)
            fields = f.read().split()
            page_size = os.sysconf("SC_PAGE_SIZE")
            return (int(fields[1]) * page_size) // 1024
    except (FileNotFoundError, AttributeError):
        return None


@pytest.fixture
def have_rss():
    return _rss_kb() is not None


# ---------------------------------------------------------------------------
# Pydantic-only tests (no FFI; always run)
# ---------------------------------------------------------------------------


class TestStorageDescriptorParsingMemory:
    """Bounds on pydantic parsing of StorageDescriptor.

    No live FFI required. These run on every host.
    """

    def _samples(self):
        return [
            '{"kind":"hardware","hardware_type":"TpmFirmware","blob_path":null}',
            '{"kind":"hardware","hardware_type":"AndroidStrongbox","blob_path":"/data/blob"}',
            '{"kind":"software_file","path":"/var/lib/ciris/agent.p256.key"}',
            '{"kind":"software_os_keyring","backend":"secret-service","scope":"user"}',
            '{"kind":"software_os_keyring","backend":"keychain","scope":"system"}',
            '{"kind":"in_memory"}',
        ]

    def test_parse_each_variant(self):
        """All four variants parse cleanly."""
        for s in self._samples():
            d = StorageDescriptor.model_validate_json(s)
            assert d.kind in StorageKind
            # Helpers don't blow up on any variant
            d.is_hardware_backed()
            d.disk_path()

    def test_parse_allocation_bound(self):
        """Repeated parsing of one descriptor stays within allocation budget."""
        sample = '{"kind":"software_file","path":"/var/lib/ciris/agent.p256.key"}'

        # Warmup — first parse triggers pydantic schema cache + interning.
        for _ in range(100):
            StorageDescriptor.model_validate_json(sample)
        gc.collect()

        # Measure
        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()
        for _ in range(1000):
            d = StorageDescriptor.model_validate_json(sample)
            assert d.kind == StorageKind.SOFTWARE_FILE

        snapshot_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        # Diff
        stats = snapshot_after.compare_to(snapshot_before, "filename")
        total_bytes = sum(s.size_diff for s in stats if s.size_diff > 0)
        per_parse = total_bytes / 1000
        # Generous bound — pydantic models hold a few internal refs
        assert per_parse < ALLOCATION_BUDGET_PER_PARSE_BYTES, (
            f"Parsing leaked {per_parse:.1f} B/parse "
            f"(budget {ALLOCATION_BUDGET_PER_PARSE_BYTES})"
        )

    def test_parse_extra_fields_rejected(self):
        """extra='forbid' protects against schema drift."""
        import pydantic

        bad = '{"kind":"in_memory","unexpected":"field"}'
        with pytest.raises(pydantic.ValidationError):
            StorageDescriptor.model_validate_json(bad)


# ---------------------------------------------------------------------------
# Live FFI tests (skipped if FFI init fails)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def live_verifier():
    """Construct a real CIRISVerify if possible; skip module otherwise.

    The TPM init in ciris_verify_init() can hang indefinitely on hosts
    with a stale TPM state. The hang holds the GIL, so a Python-level
    timeout (threading.Thread.join, pytest-timeout) cannot interrupt it.
    The only reliable kill-the-hang path is a separate subprocess.

    We gate live tests behind CIRIS_VERIFY_LIVE_TESTS=1 to avoid
    accidentally hanging CI on a misbehaving host. To run:

        CIRIS_VERIFY_LIVE_TESTS=1 python -m pytest tests/test_memory_baseline.py

    If your host has a wedged TPM, this fixture will hang. Use a clean
    container or a host without /dev/tpm0 to run the live tests.
    """
    if os.environ.get("CIRIS_VERIFY_LIVE_TESTS") != "1":
        pytest.skip(
            "Live FFI tests are opt-in (set CIRIS_VERIFY_LIVE_TESTS=1). "
            "They hang indefinitely on hosts with stale TPM state."
        )

    from ciris_verify import CIRISVerify

    try:
        verifier = CIRISVerify(skip_integrity_check=True)
    except Exception as e:
        pytest.skip(f"CIRISVerify constructor failed: {e}")

    yield verifier


class TestLiveFFIMemory:
    """Allocation + RSS bounds on the live FFI surface.

    These tests need a real handle. If the constructor fails or hangs,
    the live_verifier fixture skips the whole class.
    """

    def test_storage_descriptor_supported(self, live_verifier):
        """v1.7+ exports the new descriptor API."""
        assert live_verifier.has_storage_descriptor_support, (
            "Live library does not export ciris_verify_signer_storage_descriptor — "
            "running against pre-v1.7?"
        )

    def test_storage_descriptor_returns_valid_variant(self, live_verifier):
        d = live_verifier.storage_descriptor()
        assert isinstance(d, StorageDescriptor)
        assert d.kind in StorageKind
        # The agent process running this test will land in some
        # combination of hardware / software_file / in_memory; all are valid.

    def test_storage_descriptor_no_rss_growth(self, live_verifier):
        """1000 descriptor calls do not leak."""
        if _rss_kb() is None:
            pytest.skip("RSS tracking unavailable on this host")

        # Warmup — first calls populate caches
        for _ in range(100):
            live_verifier.storage_descriptor()
        gc.collect()

        before = _rss_kb()
        for _ in range(1000):
            d = live_verifier.storage_descriptor()
            # touch the value to defeat any deferred parsing
            assert d.kind in StorageKind
        gc.collect()
        after = _rss_kb()

        delta_kb = after - before
        assert delta_kb < RSS_STABILITY_BUDGET_KB, (
            f"RSS grew {delta_kb} KB across 1000 storage_descriptor() calls "
            f"(budget {RSS_STABILITY_BUDGET_KB} KB) — possible leak"
        )

    def test_init_rss_within_budget(self, live_verifier):
        """The initialized library + handle fit in INIT_RSS_BUDGET_MB."""
        if _rss_kb() is None:
            pytest.skip("RSS tracking unavailable on this host")
        rss_mb = _rss_kb() // 1024
        assert rss_mb < INIT_RSS_BUDGET_MB, (
            f"Process RSS {rss_mb} MB exceeds init budget {INIT_RSS_BUDGET_MB} MB"
        )
