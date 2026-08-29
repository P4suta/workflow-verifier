# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/P4suta/workflow-verifier/releases/tag/v0.1.0) - 2026-08-29

### Added

- prepare v0.1.0 release candidate
- build semantic workflow verifier

### Fixed

- derive product versions from Cargo metadata
- separate AppContainer source and scratch storage
- canonicalize AppContainer source ACL
- preserve cmd script quoting in AppContainer
- preserve source reads under AppContainer deny ACL
- encode Windows argv with native quoting rules
- use AppContainer-owned workspace storage
- honor native sandbox MSRV and child policy
- harden cross-platform CI conformance

### Other

- Unify the Rust product as one public crate ([#9](https://github.com/P4suta/workflow-verifier/pull/9))
- Optimize Rust analysis runtime and add performance gate ([#8](https://github.com/P4suta/workflow-verifier/pull/8))
- Complete Rust-first v0.1.0 candidate with TDD and mutation hardening ([#7](https://github.com/P4suta/workflow-verifier/pull/7))
- Rebuild v0.1.0 security and release contracts ([#6](https://github.com/P4suta/workflow-verifier/pull/6))
- Add v0.1.0 release evidence for e1e4725
- Fix release package input materialization
- add v0.1.0 candidate evidence
- isolate Windows process supervision
- apply canonical Rust formatting
- launch Windows workloads directly in AppContainer
