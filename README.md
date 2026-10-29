## Umiji Node

Runs Xray-core on a server and takes its config from the [Umiji](https://github.com/therewasluna/umiji) panel.

Add the node in the panel (**Nodes → Create node**); the panel shows the `docker-compose.yml` to run on the node
server. Build the image with `docker build -f docker/Dockerfile -t umiji-node .`, and see [DEV_ENV.md](DEV_ENV.md)
for local development.

## License

AGPL-3.0, see [LICENCE](LICENCE). Umiji is a modified version of Remnawave.
