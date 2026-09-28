# WatchTower Roadmap

This roadmap describes the planned direction from WatchTower 0.5.0 through 1.0.0 and the likely scaling work after 1.0. Priorities may change as features are designed and tested. GitHub milestones and issues are the source of truth for delivery status.

## 0.5.0 - Beacon

Focus: finish the current native HTTPS and notification-window work.

- Optional native HTTPS using mounted certificate and private-key files.
- Independent public and internal listener configuration for reverse proxies and OIDC callbacks.
- Immediate one-time alerts for newly discovered Critical and known-exploited vulnerabilities.
- Configured delivery windows for High, end-of-life, and repeat reminders.

## 0.6.0 - Cartographer

Focus: make application-to-CPE mapping easier to configure and safer to trust.

- Replace editable CPE fields in the application form with a read-only vulnerability-mapping summary and a dedicated in-app dialog.
- Provide advanced CPE search across any field, part, vendor, product, version, and edition.
- Display results in a larger, paginated, keyboard-accessible table with canonical CPE details.
- Allow a complete CPE 2.3 string to be pasted and parsed into a mapping.
- Support product mapping with a wildcard version and exact-CPE mapping with explicit qualifiers.
- Test a proposed mapping against NVD before it is saved and preview representative matching vulnerabilities.
- Warn about deprecated, overly broad, malformed, empty, or otherwise suspicious mappings.
- Store the canonical CPE, parsed fields, mapping mode, and last test metadata while keeping implementation fields out of the ordinary application editor.

## 0.7.0 - Vantage

Focus: make delegated access understandable and verifiable without requiring separate identity-provider test users.

- Add a persistent Permission Preview mode for administrators and delegated access administrators.
- Preview the effective access produced by a saved identity mapping or a selected combination of proposed grants before changes are saved.
- Apply previewed permissions on the server so navigation, visible resources, controls, and authorization results match the selected access.
- Keep the underlying administrator session intact and display an always-visible banner that identifies the previewed access and provides a reliable exit action.
- Keep preview sessions read-only while showing which actions the previewed access would permit.
- Explain which identity mappings, roles, scopes, resources, and combined grants produce each effective permission.
- Add a delegated Access Administrator role with safeguards that prevent it from assigning or modifying protected administrator access.
- Record access-control changes and Permission Preview activity in the audit log.
- Add automated authorization coverage for individual roles, scoped grants, combined grants, unmatched users, and protected-administrator boundaries.

## 0.8.0 - Steward

Focus: connect applications and findings to responsible teams and meaningful operational context.

- Add reusable owners with primary and escalation contact information.
- Add application context including criticality, environment, exposure, tags, and owner assignments.

## 0.9.0 - Resolve

Focus: give applicable findings a recorded and accountable response process.

- Add finding states such as New, Investigating, Remediation planned, Mitigated, Resolved, Risk accepted, Not affected, and False positive.
- Record assignee, due date, notes, actor, timestamps, and optional risk-acceptance expiration.
- Add an optional ticket URL compatible with Jira, ServiceNow, GitHub Issues, Azure DevOps, and similar systems.
- Reopen findings when relevant evidence changes or a temporary disposition expires.

## 0.10.0 - Relay

Focus: route relevant findings to the right people at the right time.

- Replace the single notification behavior with policies based on severity, exploitation evidence, application context, ownership, workspace, finding state, and age.
- Support immediate delivery, digest windows, reminder intervals, and escalation routing without requiring a ticketing-system integration.

## 0.11.0 - Signal

Focus: help users decide which applicable vulnerabilities deserve attention first.

- Enrich findings with FIRST EPSS probability and percentile data.
- Display CISA KEV required actions and remediation due dates when available.
- Present severity, predicted exploitation, confirmed exploitation, fix availability, and local application context as distinct signals.
- Produce an explainable priority decision such as Track, Attend, or Act now rather than an opaque aggregate score.
- Add priority filters and make priority signals available to notification policies.
- Clearly communicate the freshness, source, and limitations of prioritization data.

## 0.12.0 - Chronicle

Focus: make changes and remediation progress visible without requiring users to reconstruct events from raw logs.

- Retain append-only assessment events for meaningful transitions instead of saving every complete scan.
- Keep audit events and scanner assessment events distinct while presenting a unified application and finding timeline.
- Track first seen, last seen, resolved, reopened, KEV changes, material EPSS changes, lifecycle changes, source failures, and source recovery.
- Add bounded retention, rotation, and compaction controls for file-backed history.
- Provide paginated and filterable history APIs and interfaces.
- Report new, recurring, resolved, and overdue findings plus acknowledgement and remediation timing.
- Export relevant reports and history as CSV and JSON.

File-backed storage remains the default. History files should be compact, append-oriented, indexed in memory where useful, and suitable for the expected single-process deployment model.

## 1.0.0 - Keystone

Focus: establish dependable operational and compatibility guarantees around the complete workflow.

- Define versioned configuration, persisted-data, and API contracts.
- Provide validated upgrades, schema migrations, backup, restore, and recovery documentation.
- Introduce a storage abstraction so application logic does not depend directly on YAML or JSON file access.
- Add health and readiness reporting, source freshness, retry visibility, and explicit degraded-source behavior.
- Add retention controls and document supported single-instance and persistent-storage deployment boundaries.
- Complete accessibility, keyboard navigation, responsive layout, and dialog usability reviews.
- Add end-to-end coverage for application mapping, scanning, prioritization, notification, acknowledgement, disposition, and history.
- Publish administrator, operator, upgrade, backup, and troubleshooting documentation.

## Post-1.0 - Optional scalable storage

Focus: preserve the lightweight file-backed experience while allowing larger installations to adopt indexed database storage.

- Keep files as the default storage provider with no database required.
- Add an optional database provider for hundreds or thousands of applications, larger histories, integrations, reporting, and future multi-instance deployments.
- Store canonical CPE values alongside indexed parsed fields and preserve immutable application, workspace, feed, owner, and finding identifiers.
- Provide a maintenance-mode migration from files to a database with validation, record counts, checksums, and a detailed migration report.
- Preserve relationships, finding workflow, ticket links, notifications, acknowledgement state, timestamps, actors, history, and feed state during migration.
- Retain the original files as a recoverable backup and provide database-to-file export for recovery and portability.
- Select the first supported database provider during design; PostgreSQL is the likely scale-oriented option, while SQLite may be evaluated for embedded indexed storage.

The initial supported migration direction is expected to be files to database. Continuous bidirectional synchronization is not planned.

## Versioning policy

WatchTower uses `x.y.z` release numbers with a deliberate separation between fixes and features:

- `z` patch releases contain bug fixes, security fixes, dependency maintenance, and documentation corrections without adding product features.
- `y` minor releases contain backward-compatible features and enhancements and may also include accumulated fixes.
- `x` major releases are reserved for substantial product changes, major new capabilities, or compatibility-breaking changes.

Feature work is assigned to a minor or major milestone rather than being added to a planned patch release. Urgent fixes may be released from the current supported feature line without waiting for the next minor release.

## Release process

Each issue is implemented in a focused pull request assigned to its release milestone. Completed issue PRs may merge independently into `main` after review and required checks pass; these merges do not modify released container tags. Pull requests publish only their `pr-<number>` preview image.

After every issue in a milestone is complete, a final release PR updates the package version, changelog, and matching curated file in `release-notes/`. Only a change to the `version` value in `package.json` publishes the immutable version tag and updates `latest`; dependency, script, and other package-metadata changes do not trigger a release. After the tested image is published, WatchTower creates an annotated `vX.Y.Z` Git tag and a GitHub release from the curated notes. Manual workflow runs validate the source without publishing stable image tags.

Release notes summarize user-visible changes without issue or pull-request links. Each release also links to its immutable version tag in the `devynn76/watchtower` Docker Hub repository. The `latest` container tag continues to identify the newest successfully published version.

## Release branch naming

Milestone release branches use `feature/<version>-<title>`. Spaces and punctuation are removed from the title, and the first letter of each word is capitalized.

Examples:

- `feature/0.6.0-Cartographer`
- `feature/0.7.0-Vantage`
- `feature/0.8.0-Steward`
- `feature/0.9.0-Resolve`
- `feature/0.10.0-Relay`
- `feature/0.11.0-Signal`
- `feature/0.12.0-Chronicle`
- `feature/1.0.0-Keystone`

Post-1.0 work will receive names and release branches after it is divided into specific 1.x versions.
