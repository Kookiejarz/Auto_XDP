"""Exercise the production TCP option parser independently of optional kfuncs."""
import ctypes
from pathlib import Path
import platform
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "bpf/xdp_syncookie.c"


def _compilers():
    result = []
    seen = set()
    for name in ("clang", "clang-18", "clang-19"):
        path = shutil.which(name)
        if path is not None and Path(path).resolve() not in seen:
            seen.add(Path(path).resolve())
            result.append(pytest.param(path, id=name))
    return result or [pytest.param(None, id="no-clang")]


@pytest.fixture(scope="module", params=_compilers())
def compiler(request):
    if sys.platform != "linux" or request.param is None:
        pytest.skip("Linux and Clang are required")
    if not Path("/usr/include/bpf/bpf_helpers.h").is_file():
        pytest.skip("libbpf development headers are required")
    return request.param


class Parsed(ctypes.Structure):
    _fields_ = [("tsval", ctypes.c_uint32), ("wscale", ctypes.c_uint8),
                ("tstamp_ok", ctypes.c_uint8), ("wscale_ok", ctypes.c_uint8),
                ("sack_ok", ctypes.c_uint8), ("ecn_ok", ctypes.c_uint8)]


@pytest.fixture(scope="module")
def parse_options(compiler, tmp_path_factory):
    directory = tmp_path_factory.mktemp("syncookie-options")
    production = SOURCE.read_text()
    # Compile the actual function, without the unrelated maps and kernel
    # kfuncs in its translation unit. No separate parser implementation lives
    # in the fixture, so these checks exercise production parsing decisions.
    start = production.index("struct syncookie_syn_opts {")
    end = production.index("static __always_inline __u16\nsyncookie_write_synack_opts", start)
    c_file = directory / "options.c"
    c_file.write_text(
        "#include <linux/tcp.h>\n#include <bpf/bpf_helpers.h>\n"
        + production[start:end]
        + "\nvoid parse_options(unsigned char *data, unsigned int length, "
        "struct syncookie_syn_opts *out) {\n"
        "    *out = syncookie_parse_syn_opts((struct tcphdr *)data, data + length);\n}\n"
    )
    library_path = directory / "options.so"
    subprocess.run([compiler, "-O3", "-g", "-shared", "-fPIC", "-Wall", "-Werror",
                    str(c_file), "-o", str(library_path)],
                   check=True, capture_output=True, text=True)
    library = ctypes.CDLL(str(library_path))
    library.parse_options.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint,
                                     ctypes.POINTER(Parsed)]
    library.parse_options.restype = None

    def parse(options, *, flags=2, declared=None, visible=None):
        options = bytes(options)
        padded = options + bytes((-len(options)) % 4)
        declared = len(padded) if declared is None else declared
        visible = len(padded) if visible is None else visible
        assert 0 <= declared <= 40 and declared % 4 == 0
        assert 0 <= visible <= len(padded)
        packet = (ctypes.c_uint8 * 128)()
        packet[12] = (5 + declared // 4) << 4
        packet[13] = flags
        packet[20:20 + len(padded)] = padded
        out = Parsed()
        library.parse_options(packet, 20 + visible, ctypes.byref(out))
        return tuple(getattr(out, name) for name, _ in Parsed._fields_)

    return parse


@pytest.mark.parametrize("options,flags,expected", [
    ([], 2, (0, 0, 0, 0, 0, 0)),
    ([], 0xC2, (0, 0, 0, 0, 0, 1)),
    ([], 0x42, (0, 0, 0, 0, 0, 0)),
    ([3, 3, 7], 2, (0, 7, 0, 1, 0, 0)),
    ([3, 3, 255], 2, (0, 14, 0, 1, 0, 0)),
    ([4, 2], 2, (0, 0, 0, 0, 1, 0)),
    ([8, 10, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0], 2,
     (0x12345678, 0, 1, 0, 0, 0)),
    ([2, 4, 5, 180, 4, 2, 8, 10, 0x12, 0x34, 0x56, 0x78,
      0, 0, 0, 0, 1, 3, 3, 7], 0xC2, (0x12345678, 7, 1, 1, 1, 1)),
    ([1] * 8 + [3, 3, 12], 2, (0, 12, 0, 1, 0, 0)),
    ([1] * 9 + [3, 3, 13], 2, (0, 13, 0, 1, 0, 0)),
    ([1] * 10 + [3, 3, 13], 2, (0, 0, 0, 0, 0, 0)),
    ([1] * 40, 2, (0, 0, 0, 0, 0, 0)),
    ([0, 3, 3, 7], 2, (0, 0, 0, 0, 0, 0)),
    ([3, 0, 3, 7], 2, (0, 0, 0, 0, 0, 0)),
    ([3, 1, 3, 7], 2, (0, 0, 0, 0, 0, 0)),
    ([8, 10, 1, 2], 2, (0, 0, 0, 0, 0, 0)),
    ([30, 2, 3, 3, 9], 2, (0, 9, 0, 1, 0, 0)),
    ([3, 3, 4, 3, 3, 9], 2, (0, 9, 0, 1, 0, 0)),
], ids=["empty", "ecn", "partial-ecn", "wscale", "wscale-clamped", "sack",
        "timestamp", "common", "ninth-option", "tenth-option", "budget",
        "maximum-nops", "eol", "zero-length", "one-length", "past-doff",
        "unknown-kind", "duplicate-wscale"])
def test_parser_preserves_options_and_iteration_budget(parse_options, options, flags, expected):
    assert parse_options(options, flags=flags) == expected


@pytest.mark.parametrize("options,declared,visible", [
    ([3, 3, 7], 4, 0),
    ([3, 3, 7], 4, 1),
    ([3, 3, 7], 4, 2),
    ([8, 10, 1, 2, 3, 4, 5, 6, 7, 8], 12, 9),
])
def test_parser_stops_at_the_packet_boundary(parse_options, options, declared, visible):
    assert parse_options(options, declared=declared, visible=visible) == (0, 0, 0, 0, 0, 0)


def test_production_object_builds_without_failed_unroll_requests(compiler, tmp_path):
    probe = subprocess.run([compiler, "-target", "bpf", "-x", "c", "-c", "-",
                            "-o", str(tmp_path / "probe.o")], input="int probe;\n",
                           capture_output=True, text=True)
    if probe.returncode:
        pytest.skip("Clang BPF target is unavailable")
    # Match the installer: BPF's target macros alone can make Linux/glibc
    # headers select a different host ABI (for example x86's 32-bit stubs).
    arch_flags = subprocess.check_output([
        "bash", "-c",
        'source "$1"; resolve_bpf_target_arch; '
        'printf "%s\\n" "-D__TARGET_ARCH_${TARGET_ARCH}" "$HOST_ARCH_FLAG"',
        "bash", str(ROOT / "lib/setup/build.sh"),
    ], text=True).splitlines()
    multiarch = Path("/usr/include") / (platform.machine() + "-linux-gnu")
    command = [compiler, "-O3", "-g", "-target", "bpf", "-mcpu=v3",
               "-fno-stack-protector", "-Wall", "-Werror=pass-failed",
               "-I" + str(ROOT / "bpf/include")]
    command.extend(flag for flag in arch_flags if flag)
    if multiarch.is_dir():
        command.append("-I" + str(multiarch))
    command.extend(["-c", str(SOURCE), "-o", str(tmp_path / "xdp_syncookie.o")])
    subprocess.run(command, check=True, capture_output=True, text=True)
