# Contributing to WatchTower

## Branch workflow

The `main` branch represents the current accepted release state.

All changes must be developed on a dedicated branch and merged into `main` through a pull request. Do not make routine commits directly on `main`. The protected branch rules require the configured validation checks before merge.

Use short branch names that describe the work, such as:

- `feature/nvd-cpe-search`
- `fix/notification-schedule`
- `docs/deployment-guide`

Before opening a pull request:

1. Rebase or merge the current `main` branch into the working branch.
2. Run the automated test suite.
3. Document user-visible changes in `CHANGELOG.md`.
4. Confirm that credentials, secret files, scan state, logs, and local dependency caches are not committed.

Pull requests should explain what changed, why it changed, how it was tested, and any remaining operational or security considerations.

## Contribution terms

By intentionally submitting a contribution for inclusion in WatchTower, you
agree that it is provided under the Apache License 2.0, consistent with section
5 of the project license. Submit only work that you have the right to license.

Participation in the project is governed by the [code of conduct](CODE_OF_CONDUCT.md).

GitHub Actions runs the Node.js tests, source and secret analysis, dependency audit, Dockerfile lint, image vulnerability and hardening scans, CycloneDX SBOM generation, and an OWASP ZAP baseline scan for every pull request into `main`. After those checks pass, trusted same-repository pull requests publish the private `devynn76/watchtower:pr-<number>` preview image. Forked and Dependabot pull requests remain build-only and never receive Docker Hub credentials.

Completed issue PRs may merge independently without changing public release images. A final release PR changes the `version` value in `package.json` and adds the curated release notes; only that version-value change publishes `devynn76/watchtowervi:<version>` and `devynn76/watchtowervi:latest`, attaches BuildKit SBOM and provenance attestations, signs the image with Cosign, and creates the GitHub tag and release. Other `package.json` changes, including dependencies and scripts, still run all validation but do not trigger a release. Manual workflow runs validate the source but do not publish stable image tags. Repository administrators must configure the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` Actions secrets before publication.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting. Do not open a public issue for a suspected vulnerability.
