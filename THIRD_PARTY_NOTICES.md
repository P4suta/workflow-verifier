# Third-party notices

workflow-verifier is distributed under `MIT OR Apache-2.0`. Release SBOMs are
the authoritative, artifact-specific dependency inventory. This notice records
the dependency families used by v0.1.0; it does not replace their license texts.

Runtime OCaml dependencies:

- cmdliner 2.1.1 — ISC — https://erratique.ch/software/cmdliner
- otoml 1.0.5 — MIT — https://github.com/dmbaturin/otoml
- menhirLib 20250912 — LGPL-2.0-only WITH OCaml-LGPL-linking-exception
- uutf 1.0.4 — ISC — https://erratique.ch/software/uutf

Native helper dependencies:

- libc 0.2.189 — MIT OR Apache-2.0
- same-file 1.0.6 — MIT OR Unlicense
- windows-sys 0.61.2 and windows-link 0.2.1 — MIT OR Apache-2.0

Pinned build toolchains are OCaml 5.5.0, Dune 3.24.2, Rust 1.98.0, Python
3.13.7, Just 1.57.0 (CC0-1.0), and opam 2.5.2. They are represented as build
dependencies rather than runtime dependencies in the per-payload SPDX graph.

The runtime capsule and macOS boot bundle SBOM inputs must be generated from
their exact, digest-fixed package/kernel inventories. The SBOM generator does
not accept an `unknown` or floating dependency in place of that inventory.
Corresponding source archives for copyleft-covered release inputs are published
beside each release and bound by `release-evidence-v3`.
