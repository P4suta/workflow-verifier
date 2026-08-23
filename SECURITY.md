# Security policy

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/P4suta/workflow-verifier/security/advisories/new).
Do not include credentials, private workflow source, or runner evidence in a
public issue. Supported releases and compatibility guarantees are documented
in `docs/compatibility.md`.

Version `0.1.0-dev` is pre-release software and has no supported production
release line. Once a release candidate exists, supported versions and response
targets will be listed here. Reports are acknowledged as soon as practical;
publication and remediation timing are coordinated with the reporter.

The analyzer never connects to a network, changes source, reads secret values,
or executes workflow code unless the corresponding command-line opt-in is
provided. A sandbox backend that cannot establish every requested control must
fail closed.
