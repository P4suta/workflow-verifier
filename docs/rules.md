# Rule catalog contract

Every diagnostic has a stable rule ID, severity, confidence, root-relative
source span, explanation, trace, capabilities, evidence, optional safe fix, and
a help URI. The machine-readable report never emits an unclassified warning.

Rule families cover syntax/correctness, trust and taint, secret flow,
permissions, dependency integrity, authorization dominance, runtime
capabilities/effects, portability, and policy. `workflow-verifier explain
RULE_ID TARGET` prints the applicable trace and capabilities. SARIF 2.1.0
includes invocation data, partial fingerprints, and the rule help URI.

A suppression is policy data, not a comment escape hatch. It must identify one
rule and path and include reason, owner, and expiry. Expired suppression is a
finding.
