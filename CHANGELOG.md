# Changelog

## [0.4.0] - Planned

### Planned

- Add NVD CPE search and selection to the application editor so users can find an application and populate its CPE vendor, product, and related identity fields without locating them manually.

## [0.3.0] - Unreleased

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
