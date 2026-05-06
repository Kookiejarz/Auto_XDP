"""
Tests for the UDP global rate limiter algorithm (udp_global_rate_check).

Uses a Python simulation of the BPF C function to verify algorithmic
correctness without requiring kernel infrastructure.
"""
import threading
import unittest

XDP_PASS = 0
XDP_DROP = 2
UDP_GLOBAL_BATCH_BYTES = 65536

WINDOW_NS = 1_000_000_000   # 1 s
BATCH = UDP_GLOBAL_BATCH_BYTES

# rate_max smaller than one batch so two back-to-back batches always exceed it.
RATE_MAX_SMALL = BATCH - 1


# ---------------------------------------------------------------------------
# Python simulation of the CURRENT (unfixed) C behavior.
# The flush-trigger packet is dropped; subsequent small packets pass.
# ---------------------------------------------------------------------------

def make_global_state():
    return {
        "lock": threading.Lock(),
        "byte_rate_max": 0,
        "window_start_ns": 0,
        "prev_bytes": 0,
        "curr_bytes": 0,
    }


def make_percpu_local():
    return {"local_bytes": 0}


def _current(g, local, now, pkt_bytes):
    """Simulation of the current (unfixed) udp_global_rate_check()."""
    if g["byte_rate_max"] == 0:
        return XDP_PASS

    local["local_bytes"] += pkt_bytes
    if local["local_bytes"] < UDP_GLOBAL_BATCH_BYTES:
        return XDP_PASS

    to_flush = local["local_bytes"]
    local["local_bytes"] = 0

    ret = XDP_PASS
    with g["lock"]:
        if g["window_start_ns"] == 0:
            g["window_start_ns"] = now
            g["prev_bytes"] = 0
            g["curr_bytes"] = to_flush
        else:
            elapsed = now - g["window_start_ns"]
            if elapsed >= 2 * WINDOW_NS:
                g["window_start_ns"] = now
                g["prev_bytes"] = 0
                g["curr_bytes"] = to_flush
            else:
                if elapsed >= WINDOW_NS:
                    g["prev_bytes"] = g["curr_bytes"]
                    g["curr_bytes"] = 0
                    g["window_start_ns"] += WINDOW_NS
                    elapsed -= WINDOW_NS
                weighted = (g["prev_bytes"] * (WINDOW_NS - elapsed)
                            + g["curr_bytes"] * WINDOW_NS)
                threshold = g["byte_rate_max"] * WINDOW_NS
                if weighted + to_flush * WINDOW_NS > threshold:
                    ret = XDP_DROP
                else:
                    g["curr_bytes"] += to_flush
    return ret


# ---------------------------------------------------------------------------
# Desired (fixed) simulation — blocked_until_ns fast path.
# ---------------------------------------------------------------------------

def make_global_state_v2(byte_rate_max=0):
    return {
        "lock": threading.Lock(),
        "byte_rate_max": byte_rate_max,
        "window_start_ns": 0,
        "prev_bytes": 0,
        "curr_bytes": 0,
        "blocked_until_ns": 0,
    }


def make_percpu_local_v2():
    return {
        "local_bytes": 0,
        "blocked_until_ns": 0,
    }


def _v2(g, local, now, pkt_bytes):
    """Simulation of the desired (fixed) udp_global_rate_check()."""
    if g["byte_rate_max"] == 0:
        return XDP_PASS

    # Per-CPU fast path: check local block verdict without any lock.
    if local["blocked_until_ns"] != 0:
        if now < local["blocked_until_ns"]:
            local["local_bytes"] = 0
            return XDP_DROP
        local["blocked_until_ns"] = 0

    local["local_bytes"] += pkt_bytes
    if local["local_bytes"] < UDP_GLOBAL_BATCH_BYTES:
        return XDP_PASS

    to_flush = local["local_bytes"]
    local["local_bytes"] = 0

    ret = XDP_PASS
    block_until = 0

    with g["lock"]:
        # Check/clear global block under spinlock.
        if g["blocked_until_ns"] != 0:
            if now < g["blocked_until_ns"]:
                block_until = g["blocked_until_ns"]
                # Don't update g here; unlock and propagate to per-CPU.
            else:
                # Block expired — reset window for a clean slate.
                g["blocked_until_ns"] = 0
                g["window_start_ns"] = 0
                g["prev_bytes"] = 0
                g["curr_bytes"] = 0

        if block_until == 0:
            if g["window_start_ns"] == 0:
                g["window_start_ns"] = now
                g["prev_bytes"] = 0
                g["curr_bytes"] = to_flush
            else:
                elapsed = now - g["window_start_ns"]
                if elapsed >= 2 * WINDOW_NS:
                    g["window_start_ns"] = now
                    g["prev_bytes"] = 0
                    g["curr_bytes"] = to_flush
                else:
                    if elapsed >= WINDOW_NS:
                        g["prev_bytes"] = g["curr_bytes"]
                        g["curr_bytes"] = 0
                        g["window_start_ns"] += WINDOW_NS
                        elapsed -= WINDOW_NS
                    weighted = (g["prev_bytes"] * (WINDOW_NS - elapsed)
                                + g["curr_bytes"] * WINDOW_NS)
                    threshold = g["byte_rate_max"] * WINDOW_NS
                    if weighted + to_flush * WINDOW_NS > threshold:
                        block_until = now + WINDOW_NS
                        g["blocked_until_ns"] = block_until
                        ret = XDP_DROP
                    else:
                        g["curr_bytes"] += to_flush

    if block_until != 0:
        local["blocked_until_ns"] = block_until
        ret = XDP_DROP

    return ret


# ---------------------------------------------------------------------------
# Helper: send two full batches to push the global state into blocked.
# ---------------------------------------------------------------------------

def _trigger_block(g, local, now):
    """Send two back-to-back batches to trigger the rate-limit block.
    First batch initialises the window; second exceeds the limit."""
    _v2(g, local, now, BATCH)
    result = _v2(g, local, now, BATCH)
    assert result == XDP_DROP, "Expected block to be triggered"


# ---------------------------------------------------------------------------
# Tests of the CURRENT (unfixed) simulation — all must pass as a baseline.
# ---------------------------------------------------------------------------

class TestCurrentBehavior(unittest.TestCase):
    def setUp(self):
        self.g = make_global_state()
        self.g["byte_rate_max"] = RATE_MAX_SMALL
        self.local = make_percpu_local()

    def test_disabled_limiter_always_passes(self):
        self.g["byte_rate_max"] = 0
        for _ in range(100):
            self.assertEqual(_current(self.g, self.local, 1_000_000_000, BATCH), XDP_PASS)

    def test_below_limit_passes(self):
        # One batch at rate_max > BATCH → under the limit on first flush.
        self.g["byte_rate_max"] = 200 * 1024
        result = _current(self.g, self.local, 500_000_000, BATCH)
        self.assertEqual(result, XDP_PASS)

    def test_second_batch_drops_when_over_limit(self):
        now = 500_000_000
        _current(self.g, self.local, now, BATCH)   # initialises window
        result = _current(self.g, self.local, now, BATCH)
        self.assertEqual(result, XDP_DROP)

    def test_current_only_drops_flush_trigger(self):
        """After the flush trigger is dropped, small packets pass because
        local_bytes was cleared and the next batch hasn't filled yet."""
        now = 500_000_000
        _current(self.g, self.local, now, BATCH)
        _current(self.g, self.local, now, BATCH)   # trigger block

        # Small subsequent packet — PASSES (the known limitation).
        result = _current(self.g, self.local, now + 1, 1)
        self.assertEqual(result, XDP_PASS)


# ---------------------------------------------------------------------------
# Tests for the DESIRED (v2) behavior.
# ---------------------------------------------------------------------------

class TestDesiredBehavior(unittest.TestCase):
    def test_disabled_limiter_always_passes(self):
        g = make_global_state_v2(byte_rate_max=0)
        local = make_percpu_local_v2()
        for _ in range(100):
            self.assertEqual(_v2(g, local, 1_000_000_000, BATCH), XDP_PASS)

    def test_below_limit_passes(self):
        g = make_global_state_v2(byte_rate_max=200 * 1024)
        local = make_percpu_local_v2()
        result = _v2(g, local, 500_000_000, BATCH)
        self.assertEqual(result, XDP_PASS)

    def test_second_batch_drops_when_over_limit(self):
        g = make_global_state_v2(byte_rate_max=RATE_MAX_SMALL)
        local = make_percpu_local_v2()
        now = 500_000_000
        _v2(g, local, now, BATCH)
        result = _v2(g, local, now, BATCH)
        self.assertEqual(result, XDP_DROP)

    def test_small_packet_drops_immediately_after_block(self):
        """After a block is set, a 1-byte packet drops without filling a batch."""
        g = make_global_state_v2(byte_rate_max=RATE_MAX_SMALL)
        local = make_percpu_local_v2()
        now = 500_000_000
        _trigger_block(g, local, now)

        result = _v2(g, local, now + 1, 1)
        self.assertEqual(result, XDP_DROP,
                         "Packet in block window must drop without batching")

    def test_local_bytes_cleared_on_fast_path_block(self):
        """Fast-path block zeros local_bytes to prevent a burst on unblock."""
        g = make_global_state_v2(byte_rate_max=RATE_MAX_SMALL)
        local = make_percpu_local_v2()
        now = 500_000_000
        _trigger_block(g, local, now)

        local["local_bytes"] = 10_000
        _v2(g, local, now + 1, 500)
        self.assertEqual(local["local_bytes"], 0)

    def test_block_expires_after_window(self):
        """Single small packet after block expiry passes."""
        g = make_global_state_v2(byte_rate_max=RATE_MAX_SMALL)
        local = make_percpu_local_v2()
        now = 500_000_000
        _trigger_block(g, local, now)

        after = now + WINDOW_NS + 1
        result = _v2(g, local, after, 1)
        self.assertEqual(result, XDP_PASS)

    def test_window_reset_after_block_expiry(self):
        """After block expires the sliding window is reset; a single fresh
        batch is evaluated on its own and passes (not added to flood bytes)."""
        g = make_global_state_v2(byte_rate_max=RATE_MAX_SMALL)
        local = make_percpu_local_v2()
        now = 500_000_000
        _trigger_block(g, local, now)

        after = now + WINDOW_NS + 1
        # One fresh batch; with a clean window this must initialise only.
        result = _v2(g, local, after, BATCH)
        self.assertEqual(result, XDP_PASS,
                         "First batch after block expiry must pass with a clean window")

    def test_cross_cpu_block_detected_at_spinlock(self):
        """CPU B's batch flush sees the global block (set by CPU A) under
        the spinlock and drops, even before its own blocked_until_ns is set."""
        g = make_global_state_v2(byte_rate_max=RATE_MAX_SMALL)
        cpu_a = make_percpu_local_v2()
        cpu_b = make_percpu_local_v2()
        now = 500_000_000

        _trigger_block(g, cpu_a, now)

        # CPU B fills its own batch and flushes — must see the global block.
        result = _v2(g, cpu_b, now + 1, BATCH)
        self.assertEqual(result, XDP_DROP,
                         "CPU B batch flush must detect global block via spinlock")

    def test_cross_cpu_subsequent_packets_drop_after_propagation(self):
        """After CPU B's batch flush propagates the block to its local
        blocked_until_ns, small packets on CPU B drop via fast path."""
        g = make_global_state_v2(byte_rate_max=RATE_MAX_SMALL)
        cpu_a = make_percpu_local_v2()
        cpu_b = make_percpu_local_v2()
        now = 500_000_000

        _trigger_block(g, cpu_a, now)
        _v2(g, cpu_b, now + 1, BATCH)   # propagates block to cpu_b

        result = _v2(g, cpu_b, now + 2, 1)
        self.assertEqual(result, XDP_DROP,
                         "CPU B small packet must drop via fast path after propagation")


if __name__ == "__main__":
    unittest.main(verbosity=2)
