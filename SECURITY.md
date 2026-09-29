# Security policy

## Supported versions

WatchTower is under active pre-1.0 development. Security fixes are provided for
the latest published release. Upgrade to the newest available version before
reporting a problem that may already be resolved.

## Report a vulnerability

Do not report suspected vulnerabilities in a public issue, discussion, or pull
request.

Use the repository's **Security** tab and select **Report a vulnerability** to
send a private report. Include:

- The affected WatchTower version or container digest.
- The deployment and authentication configuration relevant to the issue.
- Reproduction steps or a minimal proof of concept.
- The expected and observed behavior.
- The practical impact and any known workarounds.

Do not include production credentials, tokens, certificates, personal data, or
customer data. Redact logs and configuration before attaching them.

The maintainer will make a reasonable effort to acknowledge the report, verify
the impact, coordinate a fix, and credit the reporter when requested. Please
allow time for a corrected release before public disclosure.

## Security scope

WatchTower is a triage tool. Incorrect CPE or lifecycle mappings and incomplete
upstream data can produce inaccurate results. Always confirm affected versions
and remediation guidance with the software vendor.

Reports about vulnerabilities in NVD, CISA KEV, endoflife.date, an identity
provider, an email provider, or another upstream service should be sent to that
service unless WatchTower handles the service's data unsafely.
