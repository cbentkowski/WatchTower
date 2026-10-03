# Managing images and SBOMs

Open **Package inventory** from application details, or **Manage images and SBOMs**
from an existing application editor. Image changes save independently of the
application editor; save a new application before configuring its inventory.

Application Editors, including inherited workspace grants, can add and edit image
references and labels, enable or disable images, import SBOMs, and retire images.
Viewers can inspect images, metadata, history, and components. Permission Preview
remains read-only. All permissions are enforced by the server.

Use a canonical OCI reference with an explicit registry and tag or SHA-256 digest.
Each image keeps its immutable UUID and separate inventory. Disabled images retain
unverified findings. Retirement requires the exact reference as confirmation and
cannot be reversed; historical evidence stays available. Refresh the application
after saving images or importing an SBOM to update findings. Changing a reference
requires a replacement SBOM; previous inventory cannot establish current coverage.

**Import image SBOM** selects that image in the import form. The Application scope
remains available for software without an image. Reported SBOM image metadata must
match the selected image; mismatches produce a red import error. Imports replace
only the selected scope and preserve prior revisions.

Each revision shows format, generator, generation/import times, uploader, component
counts, successful lookup time, reported image reference or digest, document
identity/version, checksum, and replacement links when supplied. Missing metadata
is explicitly Not reported. Coverage separates checked, unsupported, non-package,
stale, and failed evidence. Disabled and retired images are clearly labeled and
excluded from current coverage.

**Browse components** opens searchable pages of 50 normalized entries. Search names,
versions, PURLs, suppliers, or licenses. Expand a component for supplier-declared
licenses, paths, CPEs, hashes, and references. Dependency relationships are shown
for the page, capped at 200 edges; references to missing components remain visible.
These fields describe supplier evidence and do not prove applicability or source
support. Untrusted markup is displayed as text and supplier URLs are not fetched.
The most recent 50 previous revisions remain browsable under **Previous revisions**;
older normalized revision files remain in the persistent data directory.

Active findings are grouped by product, application inventory, or image; response
controls retain the same UUIDs and permissions. See
[reconciliation](INVENTORY_RECONCILIATION.md) for resolved history.

## Manual PR build checks

1. Open an existing application editor and choose Manage images and SBOMs. Add
   two images with explicit references and different labels. Close and reopen:
   both images should persist. Invalid or duplicate references should show errors.
2. Download Before from the inventory dialog and import it into each image and
   Application. Refresh: findings should be grouped by scope with independent IDs.
3. Inspect provenance and Browse components. Search lodash, expand its details,
   and check licenses/paths/dependencies when supplied. Large SBOMs should page
   through results; Previous revisions should stay readable after replacement.
4. Edit one label: the UUID and finding responses should remain. Disable that
   image and refresh: previous findings remain unverified. Re-enable and refresh.
   Change its reference: assessment must show an error requiring a replacement.
   Import a matching SBOM to restore coverage.
5. Retire one image. Incorrect confirmation must fail; the exact OCI reference
   allows retirement. Refresh: only that image's findings move into resolved
   history. The retired image and earlier revisions remain visible and read-only.
6. Check a viewer and Permission Preview: read-only metadata and component browsing
   work, while image changes and imports are unavailable and rejected server-side.
7. Restart and confirm image settings, provenance, revisions, finding IDs and
   notes persist. Existing editing, scoped refresh, upload errors, replacement
   reconciliation, and dialog scrolling should still work.

The Before/After test links remain for intermediate validation. Release PR #113
tracks removing these links, their endpoints, and test instructions before release.
