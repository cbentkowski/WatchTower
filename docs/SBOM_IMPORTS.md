# SBOM ingestion in Signal

API-based image configuration and SBOM ingestion are part 2 of issue #90.
Basic file import and active inventory metadata are available in application details.
Image configuration and detailed inventory views follow in the interface part. Newly imported
inventory is explicitly **awaiting assessment** and does not prove an application
is clean. The [package assessment implementation](PACKAGE_ASSESSMENT.md) connects
OSV queries and explicit inventory-only application configuration through the API.
The ingestion contracts below remain applicable.

## Supported import profile

The supported versions are SPDX JSON 2.3 and CycloneDX JSON 1.6 or 1.7. Format is
detected from document content and validated against the bundled official schemas.
Other versions, compressed documents, and scanner-result formats are rejected.
This import profile applies additional conservative limits: 5 MiB raw document,
10,000 components, nesting depth 32, 200,000 visited values, and 8,192 characters
per string. The JSON request envelope is also bounded. Validation runs in a worker
with 128 MiB old-generation heap limit and a ten-second deadline; at most two
workers run and eight wait. Busy callers must retry.

Components retain package names, versions, canonical PURLs, supplied CPEs,
supplier names, licenses, hashes, document-local references, and dependency
relationships. No CPE is guessed. Missing/invalid/unversioned PURLs and conflicting
versions remain explicit incomplete identities. Ecosystem support is determined
in the subsequent assessment part, not assumed from a valid PURL.

CycloneDX supplier vulnerability and VEX assertions retain attribution and are
not trusted assessment results. They cannot resolve or suppress WatchTower findings.
Embedded content, URLs, annotations, and paths are never executed or fetched.
The importer retains selected normalized data, not raw source documents or
unnecessary embedded content. Missing dependency targets remain references rather
than fabricated components.

## API contracts

All routes are scoped by the application UUID in the URL. SBOM content cannot
select another application. Application viewers may read inventory metadata;
Application Editors (including inherited workspace grants) may configure images
and import SBOMs. Administrators have access. Permission Preview blocks mutations.

- `GET /api/applications/<uuid>/inventory` returns images and revision metadata.
- `PUT /api/applications/<uuid>/images` accepts `{ "images": [...] }`. Each new
  image has `reference`, optional `label`, and optional `enabled`/`retired` booleans.
  Updates include the managed image IDs returned by the API and retain all previous
  entries. Retire entries instead of deleting them.
- `POST /api/applications/<uuid>/sboms` accepts an `sbom` string containing the
  original JSON document and an optional `imageId`. Explicit `null` selects
  application-level inventory; an image UUID selects that configured image.

When metadata identifies an image, omitted selection succeeds only for exactly
one matching active configured image. The importer recognizes CycloneDX container
names containing full OCI references, the `oci:image:reference` property on the
metadata component, and OCI PURLs with repository/digest information on described
SPDX packages or the CycloneDX metadata component. Reference/digest mismatch fails;
the importer does not silently reassign inventory or accept reported image metadata
as application-level inventory. Without recognizable image metadata, explicit
scope selection is required. Disabled/retired images cannot receive imports.

Normalized revisions are stored under the persistent data directory's `inventories`
folder. Each revision records uploader, application/image scope, document identity,
format/version, generator, checksum, timestamps, component counts, and assessment
state. A successful import supersedes the previous active revision in the same
scope while preserving prior normalized revisions and audit history. Application
and image scopes remain independent. Workflow reconciliation, removal reasons, and
retention controls are later work; import does not modify finding responses.

Back up this folder with the rest of the data directory. Image configuration in
this intermediate build is stored here rather than in `applications.yaml`.

## Manual checks for this PR build

1. Open an application, scroll down, close it, and reopen it or another application.
   The dialog should start at its header.
2. Use Refresh application beside Edit. Only that application should be assessed;
   unrelated application results and timestamps should remain unchanged. Associated
   shared feeds can update their shared cache without assessing other applications.
3. Verify an Application Editor can refresh its applications, including inherited
   workspace access. A Scan Operator can refresh applications it can view, even
   without Edit. View-only access and feed-edit access alone do not allow refresh.
4. While scrolled in an open dialog, refresh it. The scroll position should remain.
   The button prevents repeated clicks, reports progress, and restores on failure.
5. Permission Preview must reject refresh and import mutations server-side. Review
   source warnings after refresh; a successful request does not mean every source
   succeeded.
6. If testing ingestion by API, configure an image, import a supported SBOM into
   that image and another at application level, then restart. Inventory metadata
   should persist with separate scopes and awaiting-assessment state. Replacement
   should retain prior revision metadata. Malformed documents and mismatched images
   should fail without replacing the active inventory.
7. Existing application edits and finding responses should still persist through
   refresh and restart. The current package assessment slice adds file import controls and package findings.
   See the [current UI testing checklist](PACKAGE_ASSESSMENT.md#manual-pr-build-checks).

## Schema provenance

Bundled schemas were obtained from these versioned upstream sources:

- [SPDX 2.3 JSON schema](https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json)
- [CycloneDX 1.6 schema and supporting schemas](https://github.com/CycloneDX/specification/tree/1.6/schema)

The associated schema notices are retained in the schemas directory.

CycloneDX 1.7 uses its [versioned upstream schemas](https://github.com/CycloneDX/specification/tree/1.7/schema), including the matching SPDX license, signature, and cryptography vocabularies. Version-specific supporting schemas remain isolated during validation.
