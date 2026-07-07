# Contributing

Thanks for your interest in contributing.

This repository is a **fork**: upstream [paradigmxyz/reth](https://github.com/paradigmxyz/reth)
plus the [Chaintable pipeline](https://github.com/Chaintable/pipeline) tracer. It
runs write node(s) that produce block data for the Chaintable data pipeline, for
the chain(s) listed in this repository's CI configuration and README. It is not
a general-purpose fork of paradigmxyz/reth.

**First, determine where your change belongs:**

- **Chain client changes** (consensus, p2p, EVM, RPC, txpool) — contribute
  **upstream**, following their contributing process. We cannot accept
  chain-core changes in this fork: they would diverge from upstream and be lost
  or cause conflicts at the next upstream merge. If an upstream fix matters to
  this fork, open an issue here linking the upstream PR/commit and we will pull
  it in with the next sync.

- **Pipeline layer changes** — the pipeline tracer and its block-data output,
  the Dockerfile, published images, CI workflows, or docs about running this
  write node — contribute **here**, following the process below.

---

## Our Process (contributions to the Chaintable pipeline layer)

### Getting Started

Requirements:

* Rust (see `Cargo.toml` / `rust-toolchain`)

### Development Workflow

1. Fork the repository
2. Create a branch from `main`
3. Make changes, focused on the pipeline layer
4. Run local checks
5. Open a PR

Keep PRs small and focused.

### Local Checks (must pass)

```bash
make build
make test
```

### Code Guidelines

* Keep the diff minimal — prefer hooks over invasive edits to client code
* Match the existing code style and conventions (`gofmt`)
* Prefer simple and explicit logic
* Do not change chain-core behavior (see the top of this document)

### Testing

Changes to the pipeline layer must include tests where practical. At minimum,
describe how you verified the emitted data: chain, block range, and what you
compared it against.

### Pull Requests

Before submitting:

* Local checks pass
* Tests added or updated
* Behavior changes clearly explained

PRs should include:

* Summary
* Motivation
* Testing details
* Compatibility impact

Note on CI: it builds the Docker images for this repository, and the image
publishing steps need repository credentials, which GitHub does not provide to
pull requests from forks — those steps failing on a fork PR is expected. A
maintainer will build and verify your change on an internal branch.

### Commit Guidelines

* Use clear, descriptive messages

Example:

```
tracer: fix state-diff ordering for reorged blocks
```

### Releases

* Release tags follow `v<base-version>-ct.N` (`ct` = Chaintable; e.g.
  `v0.0.9-bsc-ct.8`); a GitHub Release publishes the versioned images

### Reporting Issues

Please include:

* Image tag or commit
* Chain and block height
* Reproduction steps
* Expected vs actual behavior

### Security

Do not disclose vulnerabilities publicly.

See [SECURITY.md](./SECURITY.md) for reporting instructions.

### License

By contributing, you agree that your contributions are licensed under the same
terms as this repository — see [LICENSE-APACHE](./LICENSE-APACHE) and
[LICENSE-MIT](./LICENSE-MIT).
