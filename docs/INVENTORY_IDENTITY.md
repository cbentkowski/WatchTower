# Inventory and package finding identity

Issue #90 is delivered in five focused changes: inventory/identity, ingestion,
package assessment, lifecycle reconciliation, and interface/documentation.
This first change establishes contracts used by subsequent changes. It does not
yet expose image configuration, SBOM uploads, or package-source queries.

The subsequent [SBOM ingestion implementation](SBOM_IMPORTS.md) connects image
configuration and imports through scoped APIs. Package-source queries and upload
controls remain later parts of the feature.

## Inventory contracts

An inventory scope is an immutable application UUID and either an immutable image
UUID or `null` for application-level inventory. Image references are configuration,
not identity: editing a reference retains the image UUID. New image IDs are generated
by WatchTower. Existing entries must be retired rather than omitted from an update;
retired entries cannot be reactivated. Callers must load the persisted previous
image list and enforce application-edit authorization before applying updates.

References require an explicit registry, lowercase repository, and tag, SHA-256
digest, or both. Registry and digest case are normalized; tag case is preserved.
Implicit registries, implicit latest tags, credentials, schemes, and whitespace
are rejected. IPv6 registries and non-SHA-256 digest algorithms are not supported
by this initial contract.

Each import receives a separate revision UUID, scope, import time, and document
checksum. The ingestion change will add normalized component provenance and
dependency relationships. Document-local component references, generator IDs,
and revision IDs must not enter cross-import finding identity.

## Finding contracts

`packageIdentity` parses PURLs using packageurl-js. A version is required and a
separately supplied version must agree. Canonical PURLs retain qualifiers and
subpaths. Locations remain exact strings: changing or omitting a location does
not silently merge components. Dependency paths are evidence, not extra installed
occurrences. Components lacking usable versioned PURLs remain unsupported inventory
evidence in the ingestion layer; they must not receive guessed identities here.

Package findings use internal random UUIDs. Matching requires the same application,
image scope, canonical versioned PURL, location, and at least one explicit advisory
ID/alias in common. CVE and GHSA case is normalized; other source IDs remain exact.
Only trusted assessment-source alias relationships may be supplied to reconciliation,
not arbitrary supplier assertions from an SBOM. Alias additions retain the UUID.

When a new alias bridges two existing identities, reconciliation returns an
`ambiguous` result containing both UUIDs without modifying either record. The
assessment/interface changes must expose this state. The workflow adapter withholds
workflow attachment for ambiguous evidence rather than selecting a response.
Unconnected source IDs cannot be inferred to represent the same advisory.

The finding store persists package identities alongside existing workflow records.
Existing application/CPE finding IDs remain compatible. Package UUIDs are used as
the existing workflow key within their application. Alias-only changes do not
reopen dispositions; material evidence changes retain existing reopening behavior.

Version/location changes currently produce distinct identities. Automatic resolution,
successor links, assignment inheritance, inventory replacement, missing-evidence
handling, and image-retirement reconciliation belong to the lifecycle change.
This foundation never resolves a finding merely because evidence is absent.
