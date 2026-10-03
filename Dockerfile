FROM node:22-trixie-slim@sha256:b26b04c123d9ff8ab646ceb18b9d75a1173acf64b9a401094b906d27b29338d4 AS build

WORKDIR /opt/watchtower
COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
    && apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/* \
    && dpkg-query -s tini > /opt/tini.status \
    && mkdir -p /opt/watchtower/data \
    && chown 1000:1000 /opt/watchtower/data

# Keep the runtime shell-free and pin the multi-architecture base image.
FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:ec2313763dd43931543bd03830466e0c409ce73a487e8d46f10db72d3b816c1c

COPY --from=build /usr/bin/tini /usr/bin/tini
COPY --from=build /opt/tini.status /var/lib/dpkg/status.d/tini
COPY --from=build /usr/share/doc/tini/copyright /usr/share/doc/tini/copyright
COPY --from=build --chown=1000:1000 /opt/watchtower/data /opt/watchtower/data
COPY --from=build /opt/watchtower/node_modules /opt/watchtower/node_modules
COPY package.json /opt/watchtower/package.json
COPY LICENSE NOTICE /opt/watchtower/
COPY src /opt/watchtower/src
COPY config /opt/watchtower/defaults

# Preserve ownership compatibility with existing persistent volumes.
USER 1000:1000
ENV USER=container HOME=/opt/watchtower/data HOST=0.0.0.0 CONFIG_DIR=/opt/watchtower/data/config DEFAULT_CONFIG_DIR=/opt/watchtower/defaults DATA_DIR=/opt/watchtower/data/state
WORKDIR /opt/watchtower
EXPOSE 4173
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/nodejs/bin/node", "-e", "const tls=String(process.env.TLS_ENABLED).toLowerCase()==='true';import(tls?'node:https':'node:http').then(({get})=>get({host:'127.0.0.1',port:process.env.SERVER_PORT||process.env.PORT||4173,path:'/healthz',rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1)))"]
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/nodejs/bin/node"]
CMD ["/opt/watchtower/src/server.mjs"]
