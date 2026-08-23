(lang dune 3.21)
(name workflow-verifier)
(version 0.1.0-dev)
(generate_opam_files true)
(source (github P4suta/workflow-verifier))
(license "MIT OR Apache-2.0")
(authors "workflow-verifier contributors")
(maintainers "workflow-verifier contributors")

(package
 (name workflow-verifier)
 (synopsis "Semantic verifier and isolated execution planner for CI workflows")
 (description
  "workflow-verifier compiles GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI into a shared phase-aware IR. It checks correctness, trust flow, secret flow, dependency integrity, least privilege, semantic changes, and fail-closed sandbox plans without invoking provider linters." )
 (depends
  (ocaml (and (>= 5.4) (< 5.6)))
  (dune (>= 3.21))))
