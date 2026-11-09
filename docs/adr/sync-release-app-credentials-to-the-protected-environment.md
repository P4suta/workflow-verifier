---
date: 2026-11-09
status: proposed
---

# Sync release App credentials to the protected environment

## Context

The release App needs credentials.
Doppler's [identity limit](https://docs.doppler.com/docs/platform-limits) constrains fleet growth.
The release-pr environment admits main and prevents administrator bypass.

## Decision

Use [native GitHub synchronization](https://docs.doppler.com/docs/github-actions) from a purpose-specific config.
Pass named secrets only to repository-scoped App token actions with explicit permissions.
Manual verification defaults to App authentication.
Signing credential verification requires explicit selection.
A callable App workflow contains only validation and the [pinned token action](https://github.com/actions/create-github-app-token/blob/64ab729a6294000f5aa4a4bc0b73d1f32bc45510/README.md).
Scope its dogfood exception by path, owner, and expiry.
The contract rejects other consumers and broader permissions.
Preserve [publication boundaries](../release.md), signing OIDC, and attestations.

## Alternatives

Doppler OIDC avoids GitHub copies and retains workflow and event claims, but consumes identity capacity.
OIDC needs no separate verification exception.
A service token adds another stored credential.

## Consequences

GitHub stores credential copies.
Protected main and environment policies replace Doppler claims.
The shared App key retains installation-wide authority.
Reconsider when the App supports workload identity.

## Confirmation

Verify synchronization and read-only App authentication from reviewed main before identity retirement.
Run the static dogfood gate locally before push.
Pause the proposal workflow during merge, then restore it.
Migration creates no release, tag, or signature.
