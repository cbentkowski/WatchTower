# WatchTower setup and upgrades

This guide covers a production-oriented Docker deployment of WatchTower. It assumes one running WatchTower container, persistent local storage, and an OpenID Connect identity provider.

## Contents

- [Initial setup](#initial-setup)
- [Requirements](#requirements)
- [Persistent storage](#persistent-storage)
- [Choose a version](#choose-a-version)
- [Configure OpenID Connect](#configure-openid-connect)
- [Create secret files](#create-secret-files)
- [Start WatchTower](#start-watchtower)
- [Complete the initial configuration](#complete-the-initial-configuration)
- [TLS and reverse proxies](#tls-and-reverse-proxies)
- [Optional runtime settings](#optional-runtime-settings)
- [Upgrade WatchTower](#upgrade-watchtower)
- [Backup and rollback](#backup-and-rollback)
- [Container troubleshooting](#container-troubleshooting)

## Initial setup

### Requirements

Before starting, prepare:

- A host with Docker Engine and Docker Compose.
- Persistent storage for `/home/container`.
- Outbound HTTPS access to NVD, CISA, endoflife.date, configured feeds, and your OpenID Connect provider.
- One inbound TCP port for native HTTPS or a trusted reverse proxy.
- An OpenID Connect client from Microsoft Entra ID, Keycloak, or another compatible provider.
- A confidential client secret stored as a mounted file or protected container secret.

WatchTower runs its own hourly scheduler. Do not create a host cron job or a second scheduler container. Run one WatchTower application instance because sessions and file-backed state are local to the process.

### Persistent storage

Mount persistent storage at `/home/container`. WatchTower creates and maintains these directories inside it:

- `/home/container/config` contains application, owner, workspace, feed, notification-policy, access-control, general, and email configuration. Notification policies, schedules, recipient routes, reminder intervals, and escalation rules are stored in `notification-policies.json`; an upgrade without that file creates equivalent default policies automatically.
- `/home/container/data` contains the latest scan, finding workflows and append-only finding history, feed cache, notification state, and system, feed, audit, and authentication logs.

Back up the entire mounted directory. Replacing a container without preserving this mount removes configuration, acknowledgement state, and locally retained results.

The image copies starter configuration into an empty mount during first startup. It also migrates legacy YAML files found directly under `/home/container` into `/home/container/config`.

### Choose a version

Use a versioned release tag in production, such as `devynn76/watchtowervi:0.8.0`. Replace `0.8.0` with the version you intend to deploy. Avoid relying on `latest` for controlled environments because it can change during a future release.

### Configure OpenID Connect

WatchTower requires OpenID Connect unless `AUTH_DISABLED=true` is explicitly used for an isolated development instance. Production deployments should configure:

| Variable | Purpose |
| --- | --- |
| `OIDC_ISSUER` | HTTPS issuer URL published by the identity provider. |
| `OIDC_CLIENT_ID` | WatchTower's confidential client ID. |
| `OIDC_CLIENT_SECRET_FILE` | Container path to the mounted client-secret file. |
| `OIDC_BASE_URL` | Public WatchTower origin, without a path, query, or fragment. |
| `OIDC_PROMPT` | Optional `select_account` or `login` behavior for each WatchTower sign-in. |
| `OIDC_ADMIN_GROUP_ID_FILE` | Container path to the exact administrator group or claim value. |
| `OIDC_REQUIRED_ROLE` | Optional baseline role required before a user may sign in. |

Register `<OIDC_BASE_URL>/auth/callback` as an allowed redirect URI. For example, an `OIDC_BASE_URL` of `https://watchtower.example.com` uses `https://watchtower.example.com/auth/callback`.

`OIDC_ISSUER` must use HTTPS. `OIDC_BASE_URL` must also use HTTPS except for a loopback-only development address. Do not include credentials or a path in either value.

Leave `OIDC_PROMPT` unset to preserve seamless SSO, including silent reuse of an existing identity-provider browser session. Set it to `select_account` when users need to choose among remembered accounts or use another account at each WatchTower sign-in. Set it to `login` when organizational policy requires users to enter credentials for every WatchTower sign-in; this is more disruptive and is not the recommended default. WatchTower rejects other values during startup. This option changes only WatchTower's authorization request; it does not require a Microsoft Entra App Registration or Enterprise Application change.

WatchTower recognizes the protected administrator group value from `OIDC_ADMIN_GROUP_ID_FILE`. It also recognizes the `WatchTower.Administrator` role value for compatibility. The administrator identity must appear in a supported `groups` or role claim.

### Create secret files

Create a directory that is readable by the container but is not part of the persistent application data or image build context:

```bash
mkdir -p ./secrets
printf '%s' 'replace-with-client-secret' > ./secrets/oidc-client-secret
printf '%s' 'replace-with-admin-group-id' > ./secrets/admin-group-id
chmod 600 ./secrets/oidc-client-secret ./secrets/admin-group-id
```

When authenticated SMTP is enabled later, create `./secrets/smtp-password` the same way. Mount secret files read-only. Do not store secret values in WatchTower YAML, commit them to Git, or bake them into the image.

### Start WatchTower

Create `compose.yaml`:

```yaml
services:
  watchtower:
    image: devynn76/watchtowervi:0.8.0
    container_name: watchtower
    restart: unless-stopped
    ports:
      - "127.0.0.1:4173:4173"
    environment:
      OIDC_ISSUER: https://login.microsoftonline.com/example-tenant/v2.0
      OIDC_CLIENT_ID: replace-with-client-id
      OIDC_CLIENT_SECRET_FILE: /run/watchtower-secrets/oidc-client-secret
      OIDC_ADMIN_GROUP_ID_FILE: /run/watchtower-secrets/admin-group-id
      OIDC_BASE_URL: https://watchtower.example.com
      # OIDC_PROMPT: select_account
    volumes:
      - watchtower-data:/home/container
      - ./secrets/oidc-client-secret:/run/watchtower-secrets/oidc-client-secret:ro
      - ./secrets/admin-group-id:/run/watchtower-secrets/admin-group-id:ro

volumes:
  watchtower-data:
```

Start the service and inspect its health:

```bash
docker compose up -d
docker compose ps
docker compose logs --tail 100 watchtower
```

The container listens on port `4173` by default and exposes `/healthz` for health checks. Binding the example to `127.0.0.1` assumes a reverse proxy runs on the same host. Change the host binding when your network design requires direct access.

### Complete the initial configuration

After the container is healthy:

1. Open the public WatchTower URL.
2. Sign in with the administrator identity.
3. Open **Settings** and save the public protocol, hostname, and port.
4. Add the first application and test its CPE and lifecycle mappings.
5. Create a workspace and assign the application.
6. Configure feeds, email delivery, and delegated access only when needed.

Continue with the [WatchTower user guide](USER_GUIDE.md#first-sign-in).

## TLS and reverse proxies

WatchTower can terminate TLS directly. Mount a PEM certificate chain and matching private key read-only, then configure:

```yaml
environment:
  TLS_ENABLED: "true"
  TLS_CERT_FILE: /run/watchtower-secrets/tls-chain.pem
  TLS_KEY_FILE: /run/watchtower-secrets/tls-key.pem
volumes:
  - ./secrets/tls-chain.pem:/run/watchtower-secrets/tls-chain.pem:ro
  - ./secrets/tls-key.pem:/run/watchtower-secrets/tls-key.pem:ro
```

WatchTower validates that both files are readable, the key matches the certificate, and TLS 1.2 or newer can be used. It fails startup instead of silently falling back to HTTP. Restart the container after replacing a certificate or key.

WatchTower may instead listen on HTTP inside a trusted container network behind an HTTPS reverse proxy. Forward the original host and protocol information, and set `OIDC_BASE_URL` plus **Settings > General** to the public HTTPS address.

## Optional runtime settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `SERVER_PORT` or `PORT` | `4173` | Internal listening port. |
| `HOST` | `0.0.0.0` in the container | Listening address. |
| `NVD_API_KEY` | None | Speeds NVD requests for larger inventories. |
| `SCAN_INTERVAL_MINUTES` | `60` | Automatic scan interval. |
| `AUTO_SCAN` | `true` | Set to `false` only when intentionally disabling scheduled scans. |
| `SMTP_PASSWORD_FILE` | None | Mounted password used by authenticated email delivery. |
| `AUTH_DISABLED` | `false` | Development-only bypass; do not use for an exposed deployment. |

The image sets its configuration and data directories. Most deployments should not override `CONFIG_DIR`, `DEFAULT_CONFIG_DIR`, or `DATA_DIR`.

## Upgrade WatchTower

Use this process for every upgrade:

1. Read the target version's GitHub release notes and note any migration or configuration requirements.
2. Confirm the current container is healthy and record the current image tag.
3. Back up the persistent `/home/container` volume and mounted secret files.
4. Change the image reference in `compose.yaml` to the target version. Do not change directly from one mutable `latest` image to another without recording both digests.
5. Pull and recreate the container:

   ```bash
   docker compose pull watchtower
   docker compose up -d watchtower
   ```

6. Review startup logs and wait for the health check to pass.
7. Sign in and verify the dashboard, application mappings, owners, workspaces, feeds, settings, and recent logs.
8. Keep the backup until the new version has completed a successful scan and notification cycle.

WatchTower performs compatible file migrations during startup. Do not interrupt the container while it is writing configuration or migration results.

## Backup and rollback

### Back up

Stop the container for the most consistent file-level backup, then copy or snapshot the complete volume mounted at `/home/container`. Back up mounted secret files separately.

At minimum, preserve the complete `config` directory, including `owners.yaml` and `notification-policies.json`, and the notification, feed, scan, and log files under `data`. WatchTower stores rotating system, feed, audit, and authentication streams in `system.jsonl`, `feed.jsonl`, `audit.jsonl`, and `auth.jsonl`; each may also have a `.previous.jsonl` rotation file. Legacy `logs.jsonl` files remain visible with the system stream after an upgrade.

### Roll back

1. Stop WatchTower.
2. Restore the pre-upgrade persistent volume snapshot when the newer version changed stored data.
3. Restore the previous image tag in `compose.yaml`.
4. Start the container and inspect its logs and health.
5. Verify sign-in and configuration before restoring normal access.

Do not run old and new versions against the same writable volume at the same time.

## Container troubleshooting

### The container exits immediately

Run `docker compose logs watchtower`. Common causes are incomplete OIDC settings, unreadable secret files, an invalid public base URL, or mismatched native TLS files.

### Sign-in redirects fail

Confirm that `OIDC_BASE_URL` exactly matches the public origin and that its `/auth/callback` URL is registered with the identity provider. Verify the issuer, client ID, secret, reverse-proxy protocol, and system time.

### The application starts with no saved configuration

Confirm that the expected persistent volume is mounted at `/home/container`. Inspect the container mounts before making new configuration changes.

### Checks cannot reach external sources

Confirm outbound HTTPS, DNS, proxy, and certificate-trust settings from the container network. NVD requests without an API key are intentionally rate limited.

### Email cannot be enabled

Authenticated delivery requires `SMTP_PASSWORD_FILE` to point to a readable, nonempty mounted file and the configured username environment variable to exist. Use **Send test email** in Settings before relying on notifications.

### Direct file editing

WatchTower stores configuration in YAML files, but direct editing is discouraged. The UI validates relationships, preserves immutable identifiers, records audit details, and prevents many malformed states. Use direct editing only for recovery with a verified backup.
