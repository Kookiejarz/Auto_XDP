# Test system

`tests/run.sh` is the stable entry point for local development and CI. Test
programs register themselves with one metadata comment instead of being listed
in workflows or runner scripts:

```bash
# auto-xdp-test-suite: component
```

Run `bash tests/run.sh list` to inspect registration and
`bash tests/run.sh distro` for the default syntax, deterministic unit,
component, and installer-smoke contracts. Privileged
environments additionally run `kernel`; installed-system jobs run `installed`
without changing the installation, then use `uninstall` for teardown and
residue checks.

Python component tests use a registered pytest marker; unmarked tests belong to
the deterministic unit layer.

Unmarked Python tests are deterministic unit contracts. They exercise public
input/output boundaries without uncontrolled time, network, subprocesses, root,
or source-text inspection; in-memory fakes are allowed. Component tests own
temporary files, CLI execution, and controlled operating-system adapters.

The `static` suite parses every maintained Python source against the minimum
supported Python 3.10 grammar, validates TOML/JSON data with standard parsers,
checks GitHub workflow YAML with PyYAML, and runs `bash -n` over every shell
source. Native C, BPF headers, and the handler Makefile are covered by `build`,
which compiles the real objects instead of approximating the toolchain parser.

All suites use structured console diagnostics. Successful stages and Bash tests
emit `[INFO]` records and preserve their normal output; expected skips or warning
text emit `[WARNING]`. Failures emit `[ERROR]` with the command, exit status,
working directory, runtime versions, and complete captured test output. Pytest
uses live INFO logging, tee capture, long tracebacks, and local-variable reports.

Bash unit programs source `tests/bash/testlib.sh` and end with:

```bash
run_discovered_tests "${BASH_SOURCE[0]}" "component"
finish_tests
```

Every top-level `test_*()` function is executed in definition order. Adding a
test no longer requires maintaining a second registry at the bottom of the
file. Python tests continue to use pytest discovery.

Tests should assert stable contracts: exit status, persisted configuration,
installed artifacts, loaded map ABI, pinned-program identity, rollback state,
and packet verdicts. Concurrency and pressure behavior belongs in a future
dedicated suite; it should not be simulated by copying the production algorithm
into Python.
