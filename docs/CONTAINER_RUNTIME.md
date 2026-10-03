# Distroless container runtime

Starting with 0.11.0, WatchTower uses Google distroless Node 22. The runtime contains no shell, npm, package manager, or OpenSSL command-line tool. Tini forwards signals to Node and reaps child processes. Native HTTPS uses Node's TLS implementation.

## Startup and storage

Compose and Kubernetes use the image defaults without command overrides:

```text
/usr/bin/tini -g -- /nodejs/bin/node /opt/watchtower/src/server.mjs
```

The image no longer interprets `STARTUP` shell commands. If a platform needs an explicit command, use the executable arguments above. The application initializes defaults and migrates legacy YAML configuration before serving requests.

The runtime uses UID 1000 and GID 1000, preserving existing volume ownership. Mount writable persistent storage at `/home/container`. Application code under `/opt/watchtower` is read-only. New Docker named volumes inherit the image directory ownership; existing volumes retain their ownership.

On Linux, provision bind-mounted data directories for `1000:1000`. Secret files must be readable by UID/GID 1000: for root-owned files, use group 1000 and mode `0440`, with parent directories traversable by that group. Do not make production private keys world-readable.

## Docker Compose

Apply these settings to the authenticated example in [SETUP.md](SETUP.md#start-watchtower). Before 0.11.0 is released, substitute the PR preview image.

```yaml
services:
  watchtower:
    image: devynn76/watchtowervi:0.11.0
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    stop_grace_period: 30s
    ports:
      - "127.0.0.1:4173:4173"
    environment:
      OIDC_ISSUER: https://identity.example.com
      OIDC_CLIENT_ID: replace-with-client-id
      OIDC_BASE_URL: https://watchtower.example.com
      OIDC_CLIENT_SECRET_FILE: /run/watchtower-secrets/oidc-client-secret
      OIDC_ADMIN_GROUP_ID_FILE: /run/watchtower-secrets/admin-group-id
    volumes:
      - watchtower-data:/home/container
      - ./secrets:/run/watchtower-secrets:ro
volumes:
  watchtower-data:
```

The image includes a Node-based Docker health check for HTTP and native HTTPS.

## Kubernetes

Create a Secret named `watchtower-oidc` in the deployment namespace with keys `oidc-client-secret` and `admin-group-id`. Substitute your issuer, client ID, public URL, and storage requirements. This example serves HTTP behind an ingress that terminates TLS; restrict direct service access to trusted callers. Before release, substitute the PR preview image.

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: watchtower-data
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: watchtower
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: watchtower
  template:
    metadata:
      labels:
        app: watchtower
    spec:
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 30
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: watchtower
          image: devynn76/watchtowervi:0.11.0
          ports:
            - name: http
              containerPort: 4173
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          env:
            - name: OIDC_ISSUER
              value: https://identity.example.com
            - name: OIDC_CLIENT_ID
              value: replace-with-client-id
            - name: OIDC_BASE_URL
              value: https://watchtower.example.com
            - name: OIDC_CLIENT_SECRET_FILE
              value: /run/watchtower-secrets/oidc-client-secret
            - name: OIDC_ADMIN_GROUP_ID_FILE
              value: /run/watchtower-secrets/admin-group-id
          startupProbe:
            httpGet:
              path: /healthz
              port: http
            periodSeconds: 5
            failureThreshold: 30
          readinessProbe:
            httpGet:
              path: /healthz
              port: http
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            periodSeconds: 30
          volumeMounts:
            - name: data
              mountPath: /home/container
            - name: oidc
              mountPath: /run/watchtower-secrets
              readOnly: true
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: watchtower-data
        - name: oidc
          secret:
            secretName: watchtower-oidc
            defaultMode: 0440
---
apiVersion: v1
kind: Service
metadata:
  name: watchtower
spec:
  selector:
    app: watchtower
  ports:
    - port: 4173
      targetPort: http
```

Run a single replica because sessions and file-backed state are local. `Recreate` avoids overlapping pods during upgrades. The storage driver must support `fsGroup`, or an administrator must provision suitable group permissions.

Kubernetes does not use Dockerfile health checks. These probes check `/healthz`; they do not guarantee upstream feed availability. For native TLS, mount a certificate/key Secret and set the TLS variables from [SETUP.md](SETUP.md#tls-and-reverse-proxies). Set `scheme: HTTPS` on all three probe HTTP requests.

## Troubleshooting and updates

Use `docker compose logs watchtower` or `kubectl logs deployment/watchtower`. Shell commands such as `docker exec ... sh` are unavailable. Invoke `/nodejs/bin/node` directly for approved diagnostic operations without printing credentials, or use an external debug container for network tools.

Tini forwards Docker's existing SIGINT and Kubernetes SIGTERM to Node. This preserves existing termination behavior; it does not add application-level draining of pending work. Stop the application before consistent file-level backups.

The Google runtime is digest-pinned. Refresh the digest deliberately for security updates, verify the upstream signature, and rerun container tests and security checks. `--pull` does not advance a pinned digest. Publish a new immutable WatchTower version for updates.
