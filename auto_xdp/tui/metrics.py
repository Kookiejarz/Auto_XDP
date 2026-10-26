"""Bounded, read-only host and interface sampling for the terminal dashboard."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
import socket


@dataclass(frozen=True)
class HostMetrics:
    hostname: str = ""
    cpu_percent: float | None = None
    cores: tuple[tuple[str, float | None], ...] = ()
    memory_used: int | None = None
    memory_total: int | None = None
    load: tuple[float, ...] = ()
    uptime: float | None = None


@dataclass(frozen=True)
class NetworkMetrics:
    iface: str = ""
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_bytes_rate: float | None = None
    tx_bytes_rate: float | None = None
    rx_packets_rate: float | None = None
    tx_packets_rate: float | None = None
    speed_mbps: int | None = None
    rx_history: tuple[float | None, ...] = ()
    tx_history: tuple[float | None, ...] = ()


class ResourceSampler:
    def __init__(self, proc_root: Path = Path("/proc"), net_root: Path = Path("/sys/class/net")) -> None:
        self.proc_root = proc_root
        self.net_root = net_root
        self.hostname = socket.gethostname()
        self._cpu: dict[str, tuple[int, int]] = {}
        self._network: tuple[tuple[str, str], float, tuple[int, ...]] | None = None
        self._rx: deque[float | None] = deque(maxlen=240)
        self._tx: deque[float | None] = deque(maxlen=240)

    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8").strip()

    def _host(self) -> HostMetrics:
        cpu: dict[str, tuple[int, int]] = {}
        percentages: dict[str, float | None] = {}
        try:
            for line in self._read(self.proc_root / "stat").splitlines():
                fields = line.split()
                if not fields or not (fields[0] == "cpu" or fields[0][3:].isdigit() and fields[0].startswith("cpu")):
                    continue
                ticks = [int(value) for value in fields[1:9]]
                if len(ticks) < 4 or min(ticks) < 0:
                    continue
                total, idle = sum(ticks), ticks[3] + (ticks[4] if len(ticks) > 4 else 0)
                name = fields[0]
                cpu[name] = (total, idle)
                previous = self._cpu.get(name)
                percent = None
                if previous is not None:
                    delta, idle_delta = total - previous[0], idle - previous[1]
                    if delta > 0 and 0 <= idle_delta <= delta:
                        percent = 100.0 * (delta - idle_delta) / delta
                percentages[name] = percent
        except (OSError, ValueError):
            cpu = {}
            percentages = {}
        self._cpu = cpu

        memory_used = memory_total = None
        try:
            memory = {}
            for line in self._read(self.proc_root / "meminfo").splitlines():
                key, value = line.split(":", 1)
                memory[key] = int(value.split()[0]) * 1024
            total = memory.get("MemTotal", 0)
            available = memory.get("MemAvailable")
            if total > 0 and available is not None and 0 <= available <= total:
                memory_total, memory_used = total, total - available
        except (OSError, ValueError, IndexError):
            pass
        load: tuple[float, ...] = ()
        uptime = None
        try:
            load = tuple(float(value) for value in self._read(self.proc_root / "loadavg").split()[:3])
        except (OSError, ValueError):
            pass
        try:
            uptime = float(self._read(self.proc_root / "uptime").split()[0])
        except (OSError, ValueError, IndexError):
            pass
        return HostMetrics(
            self.hostname, percentages.get("cpu"),
            tuple((name[3:], percent) for name, percent in percentages.items() if name != "cpu"),
            memory_used, memory_total, load, uptime,
        )

    def _interface(self, iface: str, now: float) -> NetworkMetrics:
        path = self.net_root / iface
        rates: tuple[float | None, ...] = (None,) * 4
        values: tuple[int, ...] | None = None
        speed = None
        try:
            identity = (iface, self._read(path / "ifindex"))
            values = tuple(int(self._read(path / "statistics" / name)) for name in (
                "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
            ))
            if min(values) < 0:
                raise ValueError("negative interface counter")
            previous = self._network
            if previous is not None and previous[0] == identity and now > previous[1]:
                elapsed = now - previous[1]
                rates = tuple((value - old) / elapsed if value >= old else None
                              for value, old in zip(values, previous[2]))
                if any(value is None for value in rates):
                    self._rx.clear()
                    self._tx.clear()
            else:
                self._rx.clear()
                self._tx.clear()
            self._network = (identity, now, values)
        except (OSError, ValueError):
            values = None
            self._network = None
        try:
            candidate = int(self._read(path / "speed"))
            if candidate > 0:
                speed = candidate
        except (OSError, ValueError):
            pass
        self._rx.append(rates[0])
        self._tx.append(rates[1])
        return NetworkMetrics(
            iface, values[0] if values else None, values[1] if values else None,
            rates[0], rates[1], rates[2], rates[3], speed, tuple(self._rx), tuple(self._tx),
        )

    def sample(self, iface: str, now: float) -> tuple[HostMetrics, NetworkMetrics]:
        return self._host(), self._interface(iface, now)
