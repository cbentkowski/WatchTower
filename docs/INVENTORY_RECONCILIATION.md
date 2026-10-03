# Inventory replacement and retirement

Signal part 4 of issue #90 reconciles package findings after a replacement SBOM
is assessed. Import alone leaves finding responses unchanged. A fresh, complete,
successfully persisted assessment can resolve a previous finding with one of
these reasons:

- **Version changed:** the same package family and location has another version.
- **Package removed:** that package occurrence is absent from the new revision.
- **No longer reported:** the package remains but a successful lookup no longer
  reports the advisory.
- **Image retired:** the configured image was explicitly retired.

Application-level inventory and each image are independent. A replacement for
one scope cannot resolve findings in another. Disabled images, source failures,
stale inventories, unsupported components, and inventory read failures retain
previous findings as **unverified**. Empty inventories remain incomplete under
the current assessment profile. Supplier VEX claims cannot resolve findings.

Unchanged occurrences retain their finding UUID, response, assignee, ticket, and
notes. Resolved findings appear in application details under **Resolved package
findings**, with their original UUID, resolution reason, and read-only history.
They are excluded from active finding counts and alerts. If a resolved occurrence
is reported again, its original UUID and notes return, its response becomes New,
and history records the reopening. Revision metadata links replacements through
`replacesRevisionId`, `supersededBy`, and `supersededAt`. Workflow records, revision
files, finding events, and audit logs survive restart in the persistent data directory.

Image retirement currently uses `PUT /api/applications/<uuid>/images`, with the
existing Application Editor permission. Include the managed image ID and set
`retired: true`, retaining the other entries. Retirement records its actor and
time and cannot be reversed; refresh the application to reconcile findings.
The Package inventory dialog provides Add image, Edit image (including enable/disable),
Import image SBOM, and Retire image controls. Retirement requires typing the exact
OCI reference. The editor also links to Manage images and SBOMs. Changing an image
reference invalidates its current SBOM assessment until a replacement is imported. Viewers can read resolved
history for applications they can view; Permission Preview rejects mutations.

## Manual PR build checks

1. Create an application using **Package inventory (SBOM)** and a future manual
   end-of-life date. Open **Package inventory** and download **Before** and **After**
   from the replacement test links. Both are CycloneDX 1.7 inventory documents.
2. Import Before into the Application scope and refresh that application. It
   contains lodash 4.17.20 and minimist 1.2.5. Both should produce findings when
   the live OSV source is available; advisory counts can change over time.
3. Record one lodash and one minimist finding UUID. Set their responses to
   Investigating and add distinctive notes, assignee, and ticket references.
4. Import After into the same scope and refresh. It upgrades lodash to 4.18.1
   and keeps minimist unchanged. The minimist UUID and response should remain.
   Previous lodash findings should appear under Resolved package findings with
   **version changed**, preserved notes, and a View history event. The application
   still has an active minimist finding; it should not become clean.
5. Restart and check both active and resolved history. Optionally reimport Before
   and refresh: the old lodash UUID should return as New, with its notes preserved
   and a reopening event. Resolve it again by importing After and refreshing.
6. Try an invalid upload. A red error should appear without replacing the active
   inventory. A failed or incomplete assessment must retain prior findings as
   unverified instead of automatically resolving them.
7. Check existing application refresh, editing, dialog scrolling, and finding
   responses. View-only access must not allow imports or response changes.

The generated test documents describe inventory only; they do not install any
packages. Production image contents do not include vulnerable demo SBOM files.
