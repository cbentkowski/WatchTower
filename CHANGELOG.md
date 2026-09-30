# Changelog

## Unreleased

### Fixed

- Clear stale authentication cookies and return an already-open browser interface to sign-in after a server restart or session expiration.

### Changed

- Organize application runtime modules and browser assets under `src/` while preserving local and container behavior.
- Build, scan, and publish containers only when application source or another image input changes.

## [0.8.1] - 2026-09-29

### Fixed

- Limit a newly added application's refresh to its associated feeds and preserve existing application results instead of triggering a full feed collection and reassessment.

### Changed

- Publish versioned and `latest` release images to the public `devynn76/watchtowervi` Docker Hub repository while retaining trusted pull-request previews in the private `devynn76/watchtower` repository.
- Replace deployment-specific starter inventory with disabled examples and remove the obsolete Caddy configuration.
- Add public support, contribution, issue, pull-request, and private vulnerability-reporting guidance.
- Retain only the release SBOM from security workflows while logging sanitized failure summaries for troubleshooting.
- Remove the point-in-time 0.3.0 container security report from the published tree.

## [0.8.0] - 2026-09-28

### Added

- Add reusable application owners with primary and escalation contacts, plus application criticality, environment, exposure, and tags.
- Add optional OIDC account-selection or forced-login prompting while preserving seamless SSO by default.
- Separate system, feed, audit, and authentication activity into independently rotating logs and dedicated interface views.
- Show concise identity-group matching details for sign-ins, including WatchTower mapping and role names, unmatched provider values, and group-overage status.
- Route built-in NVD, CISA KEV, lifecycle, and vendor-source activity to the feed log alongside configured custom feeds.

## [0.7.1] - 2026-09-27

### Fixed

- Remove the blocked Google Fonts request and use a same-origin-free system font stack without weakening the Content Security Policy.

## [0.7.0] - 2026-09-27

### Added

- Preview the effective permissions of saved or proposed identity-mapping and grant combinations without creating additional identity-provider users.
- Enforce Permission Preview throughout the server in a read-only session with a persistent identity banner and reliable exit action.
- Restore unsaved Access Control edits and verification selections after Permission Preview, while clearing the browser-session draft after saving or leaving Access Control.
- Explain the identity mappings, roles, scopes, resources, and combined grants that produce effective application, workspace, feed, scan, and access-administration permissions.
- Delegate access-control management through a protected Access Administrator role without granting application, feed, scan, settings, or system-administrator access.

### Security

- Prevent Permission Preview from performing mutations and bind each in-memory preview to the authenticated session that created it.
- Restrict Access Administrator assignment changes to protected administrators.

## [0.6.0] - 2026-09-27

### Added

- Replace direct CPE field editing with a dedicated vulnerability-mapping dialog and canonical CPE summary.
- Search the NVD CPE Dictionary by any field, part, vendor, product, version, and edition with paging, keyboard selection, and optional deprecated results.
- Parse complete CPE 2.3 names and support product-level or exact-CPE mapping modes.
- Test proposed mappings against NVD, preview applicable CVEs, and retain test metadata with the application.
- Warn about deprecated, overly broad, conflicting, inconclusive, and sampled mappings before they are saved.
- Search endoflife.date lifecycle products by name, alias, category, and tag with CPE-informed ranking, release-cycle previews, and installed-version validation.
- Select lifecycle mappings from an in-app dialog while retaining manual end-of-life dates and source URLs for unlisted products.

### Changed

- Migrate existing vendor, product, and edition fields to canonical CPE mappings while preserving their assessment behavior.

## [0.5.0] - 2026-09-26

### Added

- Add optional native HTTPS with mounted certificate-chain and private-key files while retaining HTTP as the default listener.
- Keep the configured public protocol, hostname, and port independent from the internal listener for reverse proxies, Istio, OIDC callbacks, and notification links.

### Security

- Fail closed at startup when native TLS is enabled with missing, empty, unreadable, malformed, or mismatched certificate files, and require TLS 1.2 or newer.
- Keep OIDC as the authentication mechanism; native HTTPS does not request or validate client certificates.

### Fixed

- Send newly discovered Critical and known-exploited vulnerability alerts immediately once, while limiting High, EOL, and repeat reminders to the configured 24-hour local-time window.

## [0.4.1] - Unreleased

### Added

- Run Gitleaks, Semgrep, npm audit, and Hadolint against every pull request.
- Build an isolated image for Trivy, Grype, and Dockle scanning before any preview or release image is published.
- Generate and retain a CycloneDX SBOM with Syft for every pull request and release build.
- Run an OWASP ZAP baseline scan against an ephemeral WatchTower instance on every pull request.
- Publish BuildKit SBOM and provenance attestations and sign main-branch images with Cosign.
- Add weekly Dependabot checks for npm, GitHub Actions, and Docker base image updates.
- Pin GitHub Actions to immutable commit digests to reduce workflow supply chain risk.
- Validate Dependabot pull requests through the complete test and security pipeline while skipping the publish job entirely, without exposing Docker Hub credentials or publishing preview images, and keep the runtime on the supported Node major release.
- Retain machine-readable reports from every security scanner for each workflow run and keep a separately named CycloneDX SBOM artifact for every image published from `main`.
- Add a resource-limited manual GitHub Actions penetration test that runs targeted live attack probes and an OWASP ZAP full active scan against a disposable local-access container, retains reports for 30 days, and never connects to production data.
- Show the running WatchTower version on the administrator-only Settings page without exposing it through unauthenticated routes.
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
