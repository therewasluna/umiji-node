```bash
docker compose -f docker-compose-dev.yml up -d
```

```bash
docker exec -it umiji-node-dev /bin/bash
```

Install NVM

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash
```

```bash
nvm install v22.12.0 && nvm use v22.12.0
```

```bash
for f in /run/s6/container_environment/*; do export "$(basename "$f")=$(cat "$f")"; done
```

```bash
# Xray-core from XTLS (use Xray-linux-arm64-v8a.zip on arm64)
curl -fsSL -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/download/v26.5.3/Xray-linux-64.zip \
    && unzip -q /tmp/xray.zip -d /tmp/xray \
    && install -m 755 /tmp/xray/xray /usr/local/bin/xray \
    && install -d /usr/local/share/xray \
    && install -m 644 /tmp/xray/geoip.dat /tmp/xray/geosite.dat /usr/local/share/xray/ \
    && rm -rf /tmp/xray /tmp/xray.zip
```
