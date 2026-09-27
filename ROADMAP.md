# WatchTower Roadmap

This roadmap describes the planned direction from WatchTower 0.5.0 through 1.0.0 and the likely scaling work after 1.0. Priorities may change as features are designed and tested. GitHub milestones and issues are the source of truth for delivery status.

## 0.5.0 — Beacon

Focus: finish the current native HTTPS and notification-window work.

- Optional native HTTPS using mounted certificate and private-key files.
- Independent public and internal listener configuration for reverse proxies and OIDC callbacks.
- Immediate one-time alerts for newly discovered Critical and known-exploited vulnerabilities.
- Configured delivery windows for High, end-of-life, and repeat reminders.

## 0.6.0 — Cartographer

Focus: make application-to-CPE mapping easier to configure and safer to trust.

- Replace editable CPE fields in the application form with a read-only vulnerability-mapping summary and a dedicated in-app dialog.
- Provide advanced CPE search across any field, part, vendor, product, version, and edition.
- Display results in a larger, paginated, keyboard-accessible table with canonical CPE details.
- Allow a complete CPE 2.3 string to be pasted and parsed into a mapping.
- Support product mapping with a wildcard version and exact-CPE mapping with explicit qualifiers.
- Test a proposed mapping against NVD before it is saved and preview representative matching vulnerabilities.
- Warn about deprecated, overly broad, malformed, empty, or otherwise suspicious mappings.
- Store the canonical CPE, parsed fields, mapping mode, and last test metadata while keeping implementation fields out of the ordinary application editor.

## 0.7.0 — Steward

Focus: connect findings to responsible teams and a recorded response process.

- Add reusable owners with primary and escalation contact information.
- Add application context including criticality, environment, exposure, tags, and owner assignments.
- Add finding states such as New, Investigating, Remediation planned, Mitigated, Resolved, Risk accepted, Not affected, and False positive.
- Record assignee, due date, notes, actor, timestamps, and optional risk-acceptance expiration.
- Add an optional ticket URL compatible with Jira, ServiceNow, GitHub Issues, Azure DevOps, and similar systems.
- Reopen findings when relevant evidence changes or a temporary disposition expires.
- Replace the single notification behavior with policies based on severity, exploitation evidence, application context, ownership, workspace, finding state, and age.
- Support immediate delivery, digest windows, reminder intervals, and escalation routing without requiring a ticketing-system integration.

## 0.8.0 — Signal

Focus: help users decide which applicable vulnerabilities deserve attention first.

- Enrich findings with FIRST EPSS probability and percentile data.
- Display CISA KEV required actions and remediation due dates when available.
- Present severity, predicted exploitation, confirmed exploitation, fix availability, and local application context as distinct signals.
- Produce an explainable priority decision such as Track, Attend, or Act now rather than an opaque aggregate score.
- Add priority filters and make priority signals available to notification policies.
- Clearly communicate the freshness, source, and limitations of prioritization data.

## 0.9.0 — Chronicle

Focus: make changes and remediation progress visible without requiring users to reconstruct events from raw logs.

- Retain append-only assessment events for meaningful transitions instead of saving every complete scan.
- Keep audit events and scanner assessment events distinct while presenting a unified application and finding timeline.
- Track first seen, last seen, resolved, reopened, KEV changes, material EPSS changes, lifecycle changes, source failures, and source recovery.
- Add bounded retention, rotation, and compaction controls for file-backed history.
- Provide paginated and filterable history APIs and interfaces.
- Report new, recurring, resolved, and overdue findings plus acknowledgement and remediation timing.
- Export relevant reports and history as CSV and JSON.

File-backed storage remains the default. History files should be compact, append-oriented, indexed in memory where useful, and suitable for the expected single-process deployment model.

## 1.0.0 — Keystone

Focus: establish dependable operational and compatibility guarantees around the complete workflow.

- Define versioned configuration, persisted-data, and API contracts.
- Provide validated upgrades, schema migrations, backup, restore, and recovery documentation.
- Introduce a storage abstraction so application logic does not depend directly on YAML or JSON file access.
- Add health and readiness reporting, source freshness, retry visibility, and explicit degraded-source behavior.
- Add retention controls and document supported single-instance and persistent-storage deployment boundaries.
- Complete accessibility, keyboard navigation, responsive layout, and dialog usability reviews.
- Add end-to-end coverage for application mapping, scanning, prioritization, notification, acknowledgement, disposition, and history.
- Publish administrator, operator, upgrade, backup, and troubleshooting documentation.

## Post-1.0 — Optional scalable storage

Focus: preserve the lightweight file-backed experience while allowing larger installations to adopt indexed database storage.

- Keep files as the default storage provider with no database required.
- Add an optional database provider for hundreds or thousands of applications, larger histories, integrations, reporting, and future multi-instance deployments.
- Store canonical CPE values alongside indexed parsed fields and preserve immutable application, workspace, feed, owner, and finding identifiers.
- Provide a maintenance-mode migration from files to a database with validation, record counts, checksums, and a detailed migration report.
- Preserve relationships, finding workflow, ticket links, notifications, acknowledgement state, timestamps, actors, history, and feed state during migration.
- Retain the original files as a recoverable backup and provide database-to-file export for recovery and portability.
- Select the first supported database provider during design; PostgreSQL is the likely scale-oriented option, while SQLite may be evaluated for embedded indexed storage.

The initial supported migration direction is expected to be files to database. Continuous bidirectional synchronization is not planned.

## Release branch naming

Milestone release branches use `feature/<version>-<title>`. Spaces and punctuation are removed from the title, and the first letter of each word is capitalized.

Examples:

- `feature/0.6.0-Cartographer`
- `feature/0.7.0-Steward`
- `feature/0.8.0-Signal`
- `feature/0.9.0-Chronicle`
- `feature/1.0.0-Keystone`

Post-1.0 work will receive names and release branches after it is divided into specific 1.x versions.
