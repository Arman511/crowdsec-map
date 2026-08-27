# Unraid deployment

No Unraid XML template is currently tracked in this repository. Run CrowdSec
Map as a regular Docker container from Unraid using the settings below, or
adapt `docker-compose.image.yml` for your Docker host.

## Container settings

- Image: `ghcr.io/arman511/crowdsec-map:latest` if that image is available to you; otherwise build from the repository with `docker-compose.yml`.
- WebUI: `http://[IP]:[PORT:8088]`
- Container port: `8088/tcp`
- Appdata mapping: `/mnt/user/appdata/crowdsec-map` to `/app/data`
- Restart policy: `unless-stopped`
- Network: put the container on the same Docker network as CrowdSec when using `LAPI_URL=http://crowdsec:8080`.

## CrowdSec access

For the LAPI source, set `DATA_SOURCE=lapi-alerts`, `LAPI_URL`,
`LAPI_LOGIN`, and `LAPI_PASSWORD`. This does not require the Docker socket.

For `auto` or `cscli`, add the read-only mapping:

```text
/var/run/docker.sock:/var/run/docker.sock:ro
```

Then set `CROWDSEC_CONTAINER=crowdsec`. The Decisions view uses `cscli`, so it
also requires this socket and a resolvable CrowdSec container name.

## Persistent data and optional logs

Keep `/app/data` mapped to Appdata. It stores the SQLite history database,
Protection aggregate, CTI cache, and optional access log. To enable IP
Investigation, mount relevant host logs read-only and set
`INVESTIGATION_LOG_PATHS` to their container paths. Use
`PROTECTION_LOG_PATHS` for Zoraxy access logs used by the Protection view.

Do not expose the Docker socket or CrowdSec LAPI beyond the trusted Docker
network. Keep credentials in Unraid's environment settings rather than in a
committed file.
