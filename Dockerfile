FROM node:25-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -d /home/container -s /bin/sh container

COPY --chown=container:container package.json package-lock.json server.mjs auth.mjs rbac.mjs feeds.mjs nvd.mjs yaml-monitor.mjs notifications.mjs settings.mjs general.mjs logger.mjs /opt/watchtower/
RUN cd /opt/watchtower \
    && npm ci --omit=dev \
    && npm cache clean --force \
    && rm -rf /root/.npm /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} +
COPY --chown=container:container web /opt/watchtower/web
COPY --chown=container:container config /opt/watchtower/defaults/
COPY --chown=container:container docker/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod 755 /entrypoint.sh

USER container
ENV USER=container HOME=/home/container HOST=0.0.0.0 CONFIG_DIR=/home/container/config DEFAULT_CONFIG_DIR=/opt/watchtower/defaults DATA_DIR=/home/container/data
WORKDIR /home/container
EXPOSE 4173
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:4173/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/entrypoint.sh"]
