## Umiji Node

Runs Xray-core on a server and takes its config from the [Umiji](https://github.com/therewasluna/umiji) panel.

## Install

On the panel's own server, tick **Node** in the panel's installer: it runs the node there and adds it to the panel
for you. For any other server, add the node in the panel: **Nodes → Create node**.

- **Automatic install**: give the panel the server's IP and root password. It logs in over SSH once, sets up Docker
  and the node, and adds it to the panel. The password is never stored.
- **Manual setup**: copy the **Secret key** the panel shows, then run the installer on the node server as root. It
  asks for the node port and the key, installs Docker if it's missing and starts the node in `/opt/umiji-node`:

  ```bash
  bash <(curl -fsSL https://raw.githubusercontent.com/therewasluna/umiji/main/install.sh) node
  ```

  Or copy the `docker-compose.yml` the panel shows (**Copy docker-compose.yml**) and run it yourself:

  ```bash
  curl -fsSL https://get.docker.com | sh
  mkdir -p /opt/umiji-node && cd /opt/umiji-node
  nano docker-compose.yml        # paste it
  docker compose up -d
  ```

  Then finish creating the node in the panel.

Either way, open the node port (`NODE_PORT`, 2222 by default) in the node server's firewall to the panel's IP only,
e.g. `ufw allow from 203.0.113.10 to any port 2222`.

The installer adds the `umiji` command. To update the node, type `umiji` and pick **Update all**; **Uninstall** removes
it. By hand: `cd /opt/umiji-node && docker compose pull && docker compose up -d`.

The image is `ghcr.io/therewasluna/umiji-node`, for x86-64 and ARM, built by GitHub Actions. To build it yourself:
`docker build -f docker/Dockerfile -t umiji-node .`. See [DEV_ENV.md](DEV_ENV.md) for local development.

## License

AGPL-3.0, see [LICENCE](LICENCE). Umiji is a modified version of Remnawave.
