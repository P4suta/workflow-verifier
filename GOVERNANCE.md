# Governance

`workflow-verifier` currently has one maintainer, `@P4suta`. There is no second
maintainer or standing independent reviewer. `@P4suta` owns release decisions,
security coordination, compatibility policy, and final review of semantic and
containment boundaries.

Decisions are evidence-driven and recorded in issues or pull requests. Changes
to versioned protocols, public schemas, stable exit codes, proof-state meaning,
or trust boundaries require an explicit compatibility analysis. Production
changes require a failing contract before implementation and an explicit
architectural self-review before merge. Release security claims use the signed
sole-maintainer attestation described in `docs/security-review.md`; they never
describe that attestation as independent review.

Additional maintainers may be invited after sustained, high-quality
contributions and demonstrated care for the project's security model. Any
change in maintainership will be recorded in this file and in repository
settings.
