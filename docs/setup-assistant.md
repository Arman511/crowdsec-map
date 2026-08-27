# Setup guide

CrowdSec Map is configured through Docker Compose environment variables. This
checkout does not include an automatic setup script or Compose override
generator.

## LAPI alerts

Create a CrowdSec watcher/machine credential using the CrowdSec documentation
or your existing CrowdSec administration workflow. Put the resulting values in
a local `.env` file next to `docker-compose.yml`:

```dotenv
LAPI_URL=http://crowdsec:8080
LAPI_LOGIN=crowdsec-map
LAPI_PASSWORD=replace-with-the-watcher-password
DATA_SOURCE=lapi-alerts
```

The `crowdsec-map` service and CrowdSec must be on the same Docker network so
the hostname in `LAPI_URL` resolves. Start the application with:

```bash
docker compose up -d --build
docker compose logs -f crowdsec-map
```

The dashboard is available at `http://localhost:8088` by default.

## `cscli` fallback and Decisions

Set `DATA_SOURCE=auto` to try LAPI alerts first and fall back to `cscli` and
sample data. The fallback requires these settings and the read-only Docker
socket mount already shown in `docker-compose.yml`:

```dotenv
CROWDSEC_CONTAINER=crowdsec
CSCLI_COMMAND=cscli alerts list -o json --limit 0
```

The Decisions view also uses `cscli` and needs `CROWDSEC_CONTAINER`. LAPI
credentials are used for alerts; `LAPI_API_KEY` is available for API clients
that need a CrowdSec bouncer key.

If Docker socket access is undesirable, use `DATA_SOURCE=lapi-alerts` and
omit the socket mount. The Decisions view will still require a data source that
can read decisions in the deployed configuration.

## Investigation logs

Mount host logs read-only into the container and set paths as they appear inside
the container:

```yaml
volumes:
  - /opt/security-stack/zoraxy/config/log:/opt/security-stack/zoraxy/config/log:ro
environment:
  INVESTIGATION_LOG_PATHS: /opt/security-stack/zoraxy/config/log/*.log*
```

Multiple paths may be separated by commas, semicolons, or newlines. The
Protection view uses `PROTECTION_LOG_PATHS` separately so authentication or
system logs do not inflate proxy traffic totals.

## CrowdSec CTI

`CTI_API_KEY` is an optional CrowdSec CTI key for on-demand IP reputation
lookups. It is separate from LAPI credentials. Create one in the CrowdSec
Console, then add it to `.env`:

```dotenv
CTI_API_KEY=replace-with-your-cti-key
```

CrowdSec Map caches lookups for `CTI_CACHE_HOURS` (default `72`) in
`CTI_CACHE_FILE` (default `data/cti-cache.json`). Do not commit `.env` or share
the key in logs or command history.

## Verify the service

```bash
curl http://localhost:8088/api/health
docker compose ps
```

The health response reports the configured data source and refresh interval.
