# Security Policy

## Supported Versions

Auto XDP is under active development. Security fixes are provided for the latest released version and the current `main` branch.

Older releases may not receive backported security fixes. Users are encouraged to upgrade to the latest available release before reporting an issue that affects an older version.

| Version        | Supported |
| -------------- | --------- |
| Latest release | ✅         |
| `main` branch  | ✅         |
| Older releases | ❌         |

## Reporting a Vulnerability

Please **do not open a public GitHub issue** for suspected security vulnerabilities.

Use GitHub's **Private Vulnerability Reporting** feature for this repository to report vulnerabilities confidentially.

When submitting a report, please include as much of the following information as possible:

* A description of the vulnerability and its potential impact.
* The affected Auto XDP version or commit.
* The affected backend or component, such as XDP/eBPF, TC, nftables, installer, or userspace daemon.
* Relevant Linux distribution, kernel version, architecture, and network configuration.
* Steps or a proof of concept that reproduce the issue.
* Relevant logs, verifier output, packet traces, or configuration excerpts.
* Any known workarounds or mitigations.

Please **avoid including secrets, credentials, private keys, or unrelated sensitive data** in reports.

### What to Expect

After a report is submitted:

1. The report will be reviewed privately.
2. We may request additional information or reproduction details.
3. If the issue is confirmed, we will work on a fix and coordinate disclosure with the reporter where appropriate.
4. A security advisory may be published after a fix or mitigation is available.
5. If the report is determined not to be a security vulnerability, we will explain the reasoning and may suggest moving the discussion to a normal GitHub issue.

Auto XDP is currently maintained by a small project team, so response times may vary. However, security reports will be prioritized over ordinary bug reports and feature requests.

## Security Scope

Examples of issues that should be reported privately include:

* Firewall or policy bypasses.
* Packets that unexpectedly bypass XDP, TC, or nftables enforcement.
* Incorrect trust, ACL, conntrack, or rate-limit behavior that creates a security boundary bypass.
* eBPF verifier or kernel interaction issues that could cause unsafe behavior.
* Privilege escalation or unintended root-level command execution.
* Unsafe installer, update, or rollback behavior.
* Vulnerabilities that allow an untrusted local or remote user to modify Auto XDP policy or state.
* Denial-of-service issues that can reliably crash or disable Auto XDP rather than merely consume the protected host's network capacity.

General bugs, performance problems, feature requests, documentation issues, and expected limitations of upstream network capacity should normally be reported through the public issue tracker.

## Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a confirmed vulnerability.

Auto XDP aims to credit security researchers who responsibly report vulnerabilities unless they prefer to remain anonymous.
