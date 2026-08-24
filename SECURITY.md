# Security policy

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/P4suta/workflow-verifier/security/advisories/new).
Do not include credentials, private workflow source, or runner evidence in a
public issue. Supported releases and compatibility guarantees are documented
in `docs/compatibility.md`.

Version `0.1.0` is the planned first supported line. Until the signed `v0.1.0`
tag and GitHub Release exist, this repository contains a release candidate, not
a published supported release. After publication, the latest `0.1.x` release
receives security fixes; earlier pre-release snapshots do not. Reports are
acknowledged as soon as practical, and publication and remediation timing are
coordinated with the reporter.

The analyzer never connects to a network, changes source, reads secret values,
or executes workflow code unless the corresponding command-line opt-in is
provided. A sandbox backend that cannot establish every requested control must
fail closed.
