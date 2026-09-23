# WatchTower 0.3.0 Container Security Report

**Image:** `docker.io/devynn76/watchtower:0.3.0`  
**Published digest:** `sha256:8ea38554c7b37e8d46b33a287e1e0806f7c7e5449140dc4d4886162bc78fa94b`  
**Platform:** `linux/amd64`  
**Scan date:** September 22, 2026  
**Base image:** Node.js 22 on Debian 12 Bookworm Slim

## Result summary

The final image passed application tests and container startup verification. Grype and Trivy found no vulnerabilities in WatchTower's four production Node.js dependencies.

The first scan found fixable vulnerabilities in npm, Yarn, and Corepack packages inherited from the Node base image. WatchTower does not use these tools at runtime, so they were removed. The hardened image was rebuilt and scanned again. Both final scans reported zero npm findings.

The remaining findings are in Debian base-image packages. At scan time, neither scanner reported an available fixed Debian package version for any remaining Critical or High finding.

## Final scanner counts

Scanner totals count a vulnerability once for every affected package. A single CVE affecting several related Debian packages therefore appears several times.

| Scanner | Critical | High | Medium | Low | Other |
|---|---:|---:|---:|---:|---:|
| Grype | 9 | 59 | 77 | 8 | 60 Negligible and 16 Unknown |
| Trivy | 4 | 52 | 96 | 82 | 5 Unknown |

- Grype reported 30 unique Critical or High vulnerability IDs.
- Trivy reported 18 unique Critical or High vulnerability IDs.
- Grype npm findings: **0**
- Trivy findings in WatchTower production Node.js dependencies: **0**
- Critical or High findings with a scanner-reported fixed package version: **0**

Differences between Grype and Trivy are expected because they use different vulnerability databases, Debian severity sources, and package matching logic.

## Remaining Critical and High package families

The remaining findings are associated with Debian operating-system packages, primarily:

- GNU C Library (`libc6`, `libc-bin`)
- OpenSSL (`libssl3`, `openssl`)
- Perl runtime (`perl-base`)
- util-linux libraries and utilities
- ncurses libraries and data
- zlib, gzip, libtasn1, and ACL libraries

These packages come from the current Debian 12 base image. The image was built using `docker build --pull`, so it used the current published Node 22 Bookworm Slim base-image digest at build time.

## Container hardening performed

- Installed production dependencies with `npm ci --omit=dev`.
- Removed npm from the runtime filesystem after dependency installation.
- Removed Yarn and Corepack from the runtime filesystem.
- Cleared npm's package cache.
- Continued running WatchTower as the unprivileged `container` user.
- Kept `tini` as PID 1 for signal handling and clean shutdown.
- Retained only the application, its four production dependencies, CA certificates, and required runtime components.

## Verification completed

- All 17 automated tests passed.
- JavaScript syntax validation passed.
- The final hardened container started successfully and listened on port 4173.
- Grype completed against a read-only exported image archive.
- Trivy completed against the same read-only exported image archive.
- The verified image was pushed to Docker Hub under the digest shown above.

## Protected administrator group configuration

WatchTower 0.3.0 can load the protected administrator group identifier from a read-only mounted file. The value is outside `rbac.yaml`, Settings, and Access Control.

Example container setting:

```text
OIDC_ADMIN_GROUP_ID_FILE=/run/watchtower-secrets/admin-group-id
```

The mounted file must contain only the exact Entra group object ID or Keycloak group claim value. The identity provider must include that value in the ID token's `groups` claim. WatchTower reads the file during every successful login, so replacing the file does not require rebuilding the image.

## Follow-up recommendation

Rebuild with `--pull` and rescan periodically. This will incorporate Debian fixes as they become available. Scanner results are a point-in-time assessment and will change as vulnerability databases and base-image packages are updated.
