FROM mcr.microsoft.com/devcontainers/base:jammy

ARG S6_OVERLAY_VERSION=3.2.3.2

RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    xz-utils \
    zstd \
    && rm -rf /var/lib/apt/lists/*

RUN S6_ARCH="$(uname -m)" \
    && curl -L -o /tmp/s6-noarch.tar.xz "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" \
    && curl -L -o /tmp/s6-arch.tar.xz "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz" \
    && xz -dc /tmp/s6-noarch.tar.xz | tar -C / -xpf - \
    && xz -dc /tmp/s6-arch.tar.xz | tar -C / -xpf - \
    && rm -f /tmp/s6-noarch.tar.xz /tmp/s6-arch.tar.xz


ENV NVM_DIR=/root/.nvm
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash \
    && . $NVM_DIR/nvm.sh \
    && nvm install v24.12.0 \
    && nvm alias default v24.12.0 \
    && nvm use default


ENV PATH="/root/.nvm/versions/node/v24.12.0/bin:${PATH}"

ARG XRAY_CORE_VERSION=v26.5.3

RUN case "$(dpkg --print-architecture)" in \
        amd64) ARCHIVE='Xray-linux-64.zip' ;; \
        arm64) ARCHIVE='Xray-linux-arm64-v8a.zip' ;; \
    esac \
    && curl -fsSL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_CORE_VERSION}/${ARCHIVE}" \
    && unzip -q /tmp/xray.zip -d /tmp/xray \
    && install -m 755 /tmp/xray/xray /usr/local/bin/xray \
    && install -d /usr/local/share/xray \
    && install -m 644 /tmp/xray/geoip.dat /tmp/xray/geosite.dat /usr/local/share/xray/ \
    && rm -rf /tmp/xray /tmp/xray.zip \
    && ln -s /usr/local/bin/xray /usr/local/bin/umiji-core


ARG ASN_LMDB_URL=https://github.com/therewasluna/umiji/releases/download/assets-1/asn-prefixes.lmdb.zst

RUN mkdir -p /var/log/xray /var/lib/umiji-node/xray /app /usr/local/share/asn \
    && echo '{}' > /var/lib/umiji-node/xray/xray-config.json \
    && curl -fsSL "${ASN_LMDB_URL}" -o /tmp/asn-prefixes.lmdb.zst \
    && zstd -d /tmp/asn-prefixes.lmdb.zst -o /usr/local/share/asn/asn-prefixes.lmdb \
    && rm -f /tmp/asn-prefixes.lmdb.zst

COPY docker/rootfs/ /
RUN chmod +x /etc/s6-overlay/scripts/init-env.sh \
    /etc/s6-overlay/s6-rc.d/xray/run \
    /etc/s6-overlay/s6-rc.d/xray-log/run

WORKDIR /app


EXPOSE 24000

ENTRYPOINT ["/init"]

CMD ["tail", "-f", "/dev/null"]
