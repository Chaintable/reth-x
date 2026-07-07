# Security Policy

This repository is a **fork**: upstream [paradigmxyz/reth](https://github.com/paradigmxyz/reth)
plus the [Chaintable pipeline](https://github.com/Chaintable/pipeline) tracer,
which exports block data (headers, transactions, call traces, receipts, events,
state diffs) to the Chaintable data pipeline.

**First, determine where the issue lives.** The key question: does it reproduce
on an unmodified upstream build?

- **Upstream issue** — reproduces on vanilla upstream (typically consensus, p2p
  networking, EVM execution, transaction pool, standard RPC, storage). It affects
  every user of the upstream client, not just this fork. **Follow the upstream
  security process, not this document:**
  https://github.com/paradigmxyz/reth/security/policy

  We pick up upstream security fixes through periodic upstream merges; please do
  not disclose upstream vulnerabilities here.

- **This fork's issue** — only reproduces with this fork's binaries or published
  images, or involves the Chaintable pipeline layer: the pipeline tracer and its
  block-data output, the Dockerfile / image build, or the CI workflows.
  **Follow our process below.**

---

## Our Process (issues in the Chaintable pipeline layer)

### Supported Versions

We provide security updates for the latest `main` branch and recent releases.

| Version | Supported |
|---------|----------|
| main    | ✅       |
| Latest release | ✅ |
| older versions   | ❌ |

### Reporting a Vulnerability

If you discover a security issue in the Chaintable pipeline layer, **do not open
a public issue**.

Please report it privately:

- GitHub Security Advisory on this repository (preferred)
- Email: bugbounty@debank.com

Include:

- Description of the issue
- Impact / severity assessment
- Steps to reproduce
- Proof of concept (if available)

### Response Process

We aim to:

- Acknowledge within **72 hours**
- Provide initial assessment within **3–5 days**
- Fix and release as soon as possible depending on severity

### Disclosure Policy

- We follow **responsible disclosure**
- Fixes may be developed privately before public release
- Credit will be given unless you request anonymity

### Scope

Typical security-relevant areas of the Chaintable pipeline layer include:

- Integrity of the emitted block data (ordering, duplication, corruption)
- The pipeline tracer and any RPC endpoints it adds
- Resource exhaustion introduced by the pipeline tracer (memory / goroutine leaks)
- The published Docker images and the build / CI pipeline

### Notes

This fork is a data producer for the
[Chaintable pipeline](https://github.com/Chaintable/pipeline): its output feeds
downstream indexing and query systems. Security issues here may propagate
downstream — please report anything suspicious.
