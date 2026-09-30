FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -d /home/container -s /bin/sh container

COPY --chown=container:container package.json package-lock.json /opt/watchtower/
RUN cd /opt/watchtower \
    && npm ci --omit=dev \
    && npm cache clean --force \
    && rm -rf /root/.npm /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} +
COPY --chown=container:container src /opt/watchtower/src
COPY --chown=container:container config /opt/watchtower/defaults/
COPY --chown=container:container docker/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod 755 /entrypoint.sh

USER container
ENV USER=container HOME=/home/container HOST=0.0.0.0 CONFIG_DIR=/home/container/config DEFAULT_CONFIG_DIR=/opt/watchtower/defaults DATA_DIR=/home/container/data
WORKDIR /home/container
EXPOSE 4173
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["node", "-e", "const tls=String(process.env.TLS_ENABLED).toLowerCase()==='true';import(tls?'node:https':'node:http').then(({get})=>get({host:'127.0.0.1',port:process.env.SERVER_PORT||process.env.PORT||4173,path:'/healthz',rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1)))"]
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/entrypoint.sh"]
