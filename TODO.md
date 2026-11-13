# Roadmap / TODO

Baseline: **v26.11.12a**. This is a working plan, not a release commitment.
The next priorities are stable distribution compatibility, a clearer operator
panel, native packages and repository inclusion, and complete, dependable
protection modules. Existing CLI, TUI, reconciliation, and module contracts
remain the starting point for this work.

## Shipped baseline

- [x] Explicit service grants, address/interface/zone scope, audit explanations,
      and approval history; discovering a listener does not grant access.
- [x] XDP enforcement and atomic nftables fallback, with readiness checks and
      upgrade/reload recovery.
- [x] Service-aware SYN-cookie protection, generation-aware Minecraft session
      proof, and optional ICMP Echo Reply validation.
- [x] Built-in/custom module discovery, installation, draft/save/apply settings,
      diagnostics, paired XDP/TC entries, and compatible private-state reuse.
- [x] Responsive TUI pages for overview, approvals, traffic, handlers, and maps,
      with versioned packet events and explicit loss accounting.
- [x] Eight-distribution installation/compile coverage and Ubuntu XDP/nftables
      end-to-end validation. The release passed 11 jobs and 35 kernel cases;
      the container matrix is not a separate-kernel compatibility matrix.

## P0 — Stabilize distribution and kernel compatibility

- [ ] Publish a support matrix that records distribution release, architecture,
      kernel, init system, driver, attachment mode, backend, and optional-module
      capabilities. Distinguish installation checks from runtime verification.
- [ ] Refresh pinned CI images against distribution support lifecycles. Cover
      Debian/Ubuntu, Fedora, openSUSE, Arch, Alpine/OpenRC, and AlmaLinux/Rocky
      with explicit tested versions and a repeatable update policy.
- [ ] Extend VM or bare-metal lifecycle tests beyond Ubuntu, including OpenRC,
      x86_64, and arm64. Exercise install, reboot, upgrade, rollback, service
      restart, disable, and uninstall on each supported configuration.
- [ ] Expand native/generic/nftables coverage across physical NICs, virtio,
      ENA, veth/bridges, IPv4/IPv6, and supported container/NAT paths. Verify
      absent-interface recovery and explain unsupported combinations clearly.
- [ ] Check dependency resolution and failure reporting for clang/LLVM,
      bpftool, BTF, kernel development files, conntrack kfuncs, Python, and
      curses. Test missing capabilities and supported fallback behavior.
- [ ] Add multi-day soak and service-churn runs. Track false drops, connection
      continuity, memory/map growth, relay loss, reconciliation latency, and
      recovery after interrupted reloads or dependency failures.
- [ ] Publish reproducible native-XDP, generic-XDP, and nftables measurements:
      hardware/kernel/configuration, packet mix, CPU, throughput, latency,
      legitimate connection success, and state-map pressure. Include the
      existing SYN-cookie mode and the host's normal TCP-cookie behavior.

Completion evidence: a versioned support matrix, reproducible test logs, and
tracked failures for every advertised environment; no silent loss of required
protection during fallback or recovery.

## P1 — Improve the operator panel (TUI)

- [ ] Make the overview show effective enforcement mode, backend and interface
      coverage, service access, traffic, and actionable health problems with
      clear units and labels. Unify spacing, colors, chart scales, and visual
      hierarchy across pages, including low-color terminal sessions.
- [ ] Improve narrow-terminal layouts, resize behavior, long-name handling,
      keyboard/mouse navigation, focus visibility, and contextual help across
      all pages. Keep essential status and actions reachable on small screens.
- [ ] Add useful search/filtering and connected detail views for services,
      approval requests, packet reasons, modules, and maps. Preserve selection
      and scroll position while live data refreshes.
- [ ] Make draft, saved, applied, failed, stale, and unknown states easy to
      distinguish. Show an approval or module change's effective policy impact
      before applying it, using the existing reconciliation/dry-run path.
- [ ] Provide a unified health view for backend probes, loaded program/map ABI,
      last successful reconciliation, relay connectivity, event loss, and
      module dependencies, with a concrete next step for each failure.
- [ ] Extend stable, versioned JSON output to existing read commands such as
      `backend`, `ports`, `conntrack`, `stats`, and `config show`; reuse existing
      approval/handler JSON rather than creating a separate panel data model.
- [ ] Measure panel CPU, memory, refresh latency, and behavior with large
      inventories or disconnected relays. Add realistic terminal interaction
      checks and update screenshots/help when workflows change.

Completion evidence: a user can discover a service, review its access, apply an
approval, inspect traffic, and resolve a module failure through clear panel
flows, with the same effective state reported by the CLI.

## P1 — Package Auto XDP and pursue repository inclusion

- [ ] Define a consistent release version source and mappings for Python and
      distribution package versions. Align package metadata, dependency ranges,
      source archives, and release notes with the published tag.
- [ ] Create distro-native packaging: Debian/Ubuntu `.deb`, RPM-based packages,
      Arch `PKGBUILD`, and Alpine `APKBUILD`. Split runtime, development files,
      and optional kernel-dependent modules where appropriate.
- [ ] Make package builds reproducible in clean builders. Resolve build/runtime
      dependencies through the package manager and define a supported BPF
      compilation strategy for each target.
- [ ] Integrate systemd/OpenRC services, configuration ownership, permissions,
      and upgrade migration with package-manager lifecycles. Installation must
      preserve audit-first behavior and require explicit service authorization.
- [ ] Define optional kernel-module delivery across kernel upgrades, including
      build/signing requirements and Secure Boot diagnostics. Keep core runtime
      installation usable when an optional module's requirements are unmet.
- [ ] Test package install, reinstall, upgrade, rollback, removal, and purge in
      clean environments. Verify configuration handling and that unrelated
      firewall rules, BPF attachments, and shared dependencies are preserved.
- [ ] Produce signed release/package metadata, checksums, source/license
      manifests, and package-manager-specific installation instructions.
- [ ] Prepare and submit packages to suitable community or official distribution
      repositories. Track each repository's maintainer, review requirements,
      submission URL, acceptance status, and ongoing version/security updates.
      Mark inclusion complete only after a package is accepted and installable
      through that repository; a build recipe alone is not repository inclusion.

Completion evidence: users can install and upgrade a tested package through a
documented package-manager source, with an identified maintainer and a working
release-update process for that source.

## P1 — Complete and harden protection modules

- [ ] Publish a capability/support matrix for SYN Cookie, Minecraft, ICMP,
      GRE, ESP, and SCTP: kernel/backend requirements, protocol checks, state,
      telemetry, configuration, and known limits. Build on the existing module
      lifecycle and SDK.
- [ ] Exercise install, configure, enable, replace, disable, and remove for every
      bundled module across supported kernels. Check XDP/TC ordering, readback,
      failed activation, rollback, restart, and ownership-aware cleanup.
- [ ] Expand compatible-state replacement and incompatible-ABI rejection tests
      under live traffic, including multiple bindings and resource pressure.
      Document which changes preserve sessions and which require a state reset.
- [ ] Extend SYN-cookie validation for retransmits, ECN, TCP options, malformed
      ACKs, secret rotation, asymmetric paths, and unavailable capabilities.
      Keep unsupported NAT handoff rejection covered by explicit tests.
- [ ] Expand Minecraft, ICMP, GRE, ESP, and SCTP protocol fixtures and malformed
      input coverage. Verify IPv4/IPv6 behavior, limits, counters, and false
      drops against legitimate traffic; check generation/tuple isolation and
      expiry wherever a module uses session or conntrack state.
- [ ] Test ICMP dependency builds, loading, and activation after kernel upgrades
      on supported distributions, including missing headers/BTF and rejected
      signatures. Make remediation visible in both CLI and TUI.
- [ ] Improve manifest/schema validation, module version/dependency metadata,
      example modules, and author documentation. Give each module actionable
      build/load diagnostics and focused smoke tests before activation.
- [ ] Measure per-module CPU, map memory, state capacity, and telemetry overhead.
      Add new protection profiles only with a defined protocol scope, legitimate
      traffic fixtures, and reproducible validation results.

Completion evidence: each supported module has documented boundaries, usable
configuration, clear diagnostics, lifecycle/protocol tests, and measured costs;
required protection never silently becomes a generic allow rule.

## Later — Queries, integrations, and risk assessment

- [ ] Add `axdp inspect` for an IP, port, or flow, combining effective policy,
      ACL/trust decisions, conntrack, protection limits, and packet reasons.
- [ ] Keep bounded local event history with configurable retention for time-range
      queries; begin with standard-library storage such as `sqlite3`.
- [ ] Add Prometheus/OpenTelemetry export once the query/JSON contract is stable.
      Introduce a versioned local control API only for a concrete consumer that
      the existing CLI cannot support adequately.
- [ ] Develop explainable, decaying risk scores from bounded telemetry. Validate
      signals, confidence, false positives, and retention in observe-only mode
      before proposing any automatic response.
- [ ] Backtest rolling baselines and mitigation recommendations against replayed
      incidents. Keep responses opt-in, time-bounded, and reversible; consider
      trained models only when sufficient labeled evidence supports them.
- [ ] Consider signed policy bundles, multi-host coordination, and additional
      threat-intelligence feeds when real deployments require them, preserving
      provenance, freshness, and last-known-good state on refresh failures.

Keep this file and `CHANGELOG.md` aligned with releases: move completed work into
the shipped baseline or changelog, and retain only concrete follow-up tasks.
