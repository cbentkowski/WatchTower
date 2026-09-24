# Changelog

## [0.4.1] - Unreleased

### Added

- Run Gitleaks, Semgrep, npm audit, and Hadolint against every pull request.
- Build an isolated image for Trivy, Grype, and Dockle scanning before any preview or release image is published.
- Generate and retain a CycloneDX SBOM with Syft for every pull request and release build.
- Run an OWASP ZAP baseline scan against an ephemeral WatchTower instance on every pull request.
- Publish BuildKit SBOM and provenance attestations and sign main-branch images with Cosign.
- Add weekly Dependabot checks for npm, GitHub Actions, and Docker base image updates.
- Pin GitHub Actions to immutable commit digests to reduce workflow supply chain risk.
- License WatchTower under the Apache License 2.0.

### Security

- Gate Docker Hub preview and release publishing on successful tests, source analysis, secret scanning, dependency auditing, image vulnerability scanning, image hardening checks, and dynamic application scanning.

## [0.4.0] - 2026-09-23

### Added

- Add NVD CPE search and selection to the application editor.
- Add reusable RSS, Atom, JSON, HTML, and GitHub advisory feeds with application associations, cached collection state, test previews, and normalized security, release, and lifecycle evidence.
- Add a dedicated Feeds interface with immutable feed IDs, audit logging, error visibility, and application associations.
- Add Feed Viewer, Feed Editor, and Feed Manager RBAC roles with a new feed grant scope.
- Add an SMTP test button that sends with the currently entered settings without saving them.
- Load authenticated SMTP passwords from the mounted secret file named by `SMTP_PASSWORD_FILE`, verify it before enabling delivery, and reread it for tests and scheduled messages so rotations do not require a rebuild.

### Security

- Treat every fetched feed as untrusted data, remove scripts, styles, tags, control characters, and event-handler markup before storage or display, and never execute or import feed content.
- Restrict feeds to public HTTPS destinations on the standard port, reject credentials and private, loopback, link-local, internal, and metadata-service addresses, revalidate redirects and DNS results, and enforce time, redirect, entry, and ten-megabyte response limits.
- Add a restrictive Content Security Policy and move theme initialization into a same-origin script so inline feed content cannot become executable browser code.

### Fixed

- Query NVD with a product-level wildcard CPE and evaluate each returned CVE's affected version ranges locally, so versions covered by ranges are assessed even when NVD has no exact-version CPE entry.
- Refresh only the edited application's associated feeds and assessment after an application save instead of rerunning every application check.

## [0.3.5] - 2026-09-22

### Added

- Publish internal pull request builds to Docker Hub with a stable `pr-<number>` preview tag for deployment testing before merge.

### Changed

- Keep forked pull requests build-only so Docker Hub credentials are never exposed to untrusted contributions.

## [0.3.4] - 2026-09-22

### Added

- Add branded WatchTower login and successful sign-out pages with explicit identity provider sign-in actions.

### Changed

- Clear both the WatchTower session and pending OIDC flow cookies during logout and stop automatically restarting OIDC authentication.

## [0.3.3] - 2026-09-22

### Fixed

- Continue evaluating trusted same-origin browser metadata when a reverse proxy supplies an `Origin` header that differs from the configured public origin.

## [0.3.2] - 2026-09-22

### Fixed

- Accept same-origin `Referer` and browser fetch-site evidence when an `Origin` header is unavailable, preventing valid logout requests from being rejected behind a reverse proxy while retaining cross-site request protection.

## [0.3.1] - 2026-09-22

### Added

- Document a branch-first contribution workflow with pull requests into `main`.
- Add GitHub Actions validation for pull requests and automated version plus `latest` image publishing to Docker Hub after changes reach `main`.
- Add the standard `npm test` command used by local development and continuous integration.

## [0.3.0] - 2026-09-22

### Fixed

- Update application and workspace names throughout the dashboard immediately after saving an edit.
- Generate immutable UUIDs for applications and workspaces, migrate legacy IDs automatically, and keep IDs out of editable form fields.
- Show the OIDC UPN or email address in audit logs instead of the provider's opaque subject ID.

### Added

- Recognize the predefined `WatchTower.Administrator` OIDC app role and provide administrators with configuration, refresh, settings, and log access while other authenticated users receive a read-only dashboard.
- Add administrator managed identity mappings and multi role grants for global, workspace, and application access.
- Add standard roles for viewing, editing applications, managing workspace names, memberships and notifications, and running scans.
- Add a protected administrator group ID loaded from a read-only mounted file outside web-managed configuration.
- Remove npm, Yarn, and Corepack build tooling from the runtime image to reduce its vulnerability surface.

## [0.2.0]

### Added

- OIDC authentication.

## [0.1.0]

### Added

- Initial application.
