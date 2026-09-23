# Changelog

## [0.4.0] - Planned

### Planned

- Add NVD CPE search and selection to the application editor so users can find an application and populate its CPE vendor, product, and related identity fields without locating them manually.

## [0.3.3] - Unreleased

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
