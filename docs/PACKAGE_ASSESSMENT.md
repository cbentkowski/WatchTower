# Package vulnerability assessment in Signal

This is part 3 of issue #90. Active application-level and enabled image-level
inventories are checked against OSV during normal scheduled, full, and individual
application refreshes. Users do not need to regenerate an SBOM for newly published
advisories to become findings. The next part handles replacement/retirement
lifecycle reconciliation; the last part provides inventory management controls.

## Supported identities and coverage

The initial integration supports versioned, unqualified PURLs for npm, PyPI,
Maven, Go, crates.io, RubyGems, Packagist, NuGet, Hex, and Pub. Locations/subpaths
remain occurrence evidence. Missing/invalid identities, conflicting versions,
unversioned PURLs, other ecosystems, and qualified PURLs are counted as unsupported
or incomplete. This initial profile deliberately excludes distribution packages
such as Debian/RPM/Alpine: safely handling distribution versions, source/binary
mapping, and backports requires further source-specific work.

Supplied package CPEs are retained but not used by OSV. No CPE is inferred.
Supplier vulnerability/VEX assertions cannot suppress findings or override
WatchTower responses. A valid PURL does not guarantee that OSV has complete
coverage for that package. An empty successful result means no known matches in
the supported queried source, not a guarantee that the software is secure.

OSV receives eligible package names and installed versions through their PURLs.
No SBOM file, supplier assertions, dependency graph, application name, image
reference, private registry credentials, or package location is uploaded to OSV.
Private package names represented by eligible PURLs can still be disclosed by
the lookup; consider that when choosing what inventory to import.

## Evidence and finding identity

The batch API provides advisory IDs, followed by full advisory record retrieval.
Findings retain exact package/version/scope, component references, installation
locations, dependency relationships, advisory IDs/aliases, affected ranges,
fixed-version evidence, source severity data, references, and lookup time.
Full records must identify the queried package. Untrusted references are retained
only as HTTPS links without credentials and are never followed by the assessor.

Explicit aliases correlate advisories within an occurrence; unrelated identifiers
do not. Each image, installed version, and location remains separate. Existing
finding UUIDs and responses survive alias growth. Ambiguous bridges between
existing response records remain visible with response editing withheld.
Material applicability/severity/exploitation evidence can reopen dispositions;
alias IDs and display/source URLs alone do not.

Numeric scores are not invented from source labels. Explicit source severity
labels are used where available, and raw CVSS vectors remain in source evidence.
CVSS vectors without an interpreted severity label display Unknown/Not scored
and prevent a clean status when a finding exists. Critical label/known-exploited
findings participate in existing immediate notification policies without needing
an invented numeric score. This change does not calculate an upgrade target.

## Bounds, failures, and freshness

Queries contain at most 100 packages. Each package can paginate up to ten pages;
only queries with outstanding tokens are repeated. Repeated or malformed tokens,
result-count mismatches, and malformed records produce incomplete evidence.
Each inventory is limited to 200 HTTP attempts (including retries), 1,000 distinct
advisories, and 10,000 candidate finding occurrences. Requests are paced at least
100 ms apart; the current assessment loop uses serial bounded requests. A request
has a 15-second timeout and a 2 MiB response limit.
Each inventory also has a 60-second network-work budget; exceeding it produces
incomplete evidence while preserving findings already retrieved.
Record processing is limited to depth 24, 100,000 values, and 16,000 characters
per string; records exceeding these limits remain incomplete evidence.

429 and selected server errors retry at most twice. Retry-After delays over two
seconds defer work until another assessment rather than blocking for a long time.
Only advisory details are cached, for up to six hours/500 entries and only while
the batch-reported modification timestamp is unchanged. Package queries always
run again so the detail cache does not hide newly reported advisories.

Each revision exposes checked time, last successful lookup, supported/assessed/
unsupported counts, source errors, and source state through the inventory API.
Normalized assessment results persist beside their revision and survive restart.
Missing SBOMs on enabled images, an empty inventory, unsupported components,
stale inventories, and failed lookups remain incomplete/unknown. Previously
reported findings for the same revision are retained as unverified when a lookup
is incomplete. No finding is resolved merely because a lookup failed or omitted
evidence; explicit replacement/removal reconciliation follows in part 4.

`SBOM_MAX_AGE_DAYS` defaults to 30 and accepts integers from 1 to 3650. Freshness
uses generation time when supplied, otherwise import time (with the basis exposed
in assessment metadata). Invalid dates or generation times over a day in the
future are incomplete. Successful intelligence lookup cannot make an old inventory
fresh. Red findings remain red even when evidence is incomplete; incomplete
evidence prevents a green result.

## CPE-less applications

The application API accepts `assessmentMode: "inventory"` to explicitly configure
inventory assessment without a CPE. Existing CPE-backed applications keep their
default behavior and may independently add SBOM scopes. Before a usable import,
an inventory application remains awaiting assessment. Existing lifecycle
configuration is still required and its uncertainty remains visible.

In Add/Edit application, select **Package inventory (SBOM)** as the assessment
source to save without a CPE. A lifecycle product or manual end-of-life date is
still required. Existing product applications can also import package inventory.
Open an application and choose **Package inventory** in its Assessment section.
The dialog shows active imports and lets Application Editors import a file at
application level or into an already configured active image. Viewers can inspect
metadata; Permission Preview cannot import. Image configuration, retirement,
detailed component browsing, and attribution remain in the final interface part.

## Manual PR build checks

1. Add an application with **Package inventory (SBOM)** as its assessment source,
   an installed version, and a future manual end-of-life date. Save without a CPE.
   It should be Unknown before import. Existing applications can also import SBOMs.
2. Open **Package inventory** in the application's Assessment section. Download
   the demo SBOM from this dialog, choose it with the file picker, select Application,
   and click **Import SBOM**. The import time and component count should appear.
3. Close the inventory dialog and click **Refresh application**. The deliberately
   old lodash version should produce source-backed package findings with exact
   package/version/PURL context. Numeric severity must not be fabricated.
4. Update a package finding's response, add notes/ticket, refresh, and restart.
   Its UUID and response should remain stable. Reopen inventory to verify persistence.
5. Try importing invalid JSON: an error should appear and the previous active
   inventory should remain. Unsupported components and stale inventories should
   produce incomplete evidence after refresh, never a false clean result.
6. Viewer sessions can inspect inventory but cannot import. Permission Preview
   must not offer imports; the server also rejects mutations.
7. Confirm existing product applications, CPE selection, edits, scoped refresh,
   and dialog scrolling still work.

The demo contains inventory data, not software to install. Image configuration
and full inventory management follow in the interface slice.

Sources: [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/),
[OSV advisory retrieval](https://google.github.io/osv.dev/get-v1-vulns/).
