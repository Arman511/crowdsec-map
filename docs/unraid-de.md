# Unraid-Bereitstellung

In diesem Repository ist derzeit keine Unraid-XML-Vorlage enthalten. CrowdSec
Map kann in Unraid als normaler Docker-Container eingerichtet werden. Die
Einstellungen aus `docker-compose.image.yml` können als Vorlage dienen.

## Container-Einstellungen

- Image: `ghcr.io/arman511/crowdsec-map:latest`, sofern dieses Image verfügbar ist; alternativ das Image mit `docker-compose.yml` selbst bauen.
- WebUI: `http://[IP]:[PORT:8088]`
- Container-Port: `8088/tcp`
- Appdata-Einbindung: `/mnt/user/appdata/crowdsec-map` nach `/app/data`
- Neustart-Richtlinie: `unless-stopped`
- Netzwerk: Bei `LAPI_URL=http://crowdsec:8080` müssen CrowdSec Map und CrowdSec im selben Docker-Netzwerk liegen.

## CrowdSec-Zugriff

Für LAPI `DATA_SOURCE=lapi-alerts`, `LAPI_URL`, `LAPI_LOGIN` und
`LAPI_PASSWORD` setzen. Dafür ist kein Docker-Socket nötig.

Für `auto` oder `cscli` zusätzlich diese schreibgeschützte Einbindung setzen:

```text
/var/run/docker.sock:/var/run/docker.sock:ro
```

Danach `CROWDSEC_CONTAINER=crowdsec` setzen. Die Decisions-Ansicht verwendet
`cscli` und benötigt daher ebenfalls diesen Socket und einen erreichbaren
CrowdSec-Containernamen.

## Persistente Daten und Logs

`/app/data` dauerhaft auf Appdata abbilden. Dort liegen SQLite-Verlauf,
Protection-Aggregat, CTI-Cache und das optionale Zugriffsprotokoll. Für die
IP-Untersuchung relevante Host-Logs schreibgeschützt einbinden und ihre
Container-Pfade in `INVESTIGATION_LOG_PATHS` eintragen. Für die Protection-
Ansicht `PROTECTION_LOG_PATHS` verwenden.

Den Docker-Socket und die CrowdSec-LAPI nicht außerhalb des vertrauenswürdigen
Docker-Netzwerks verfügbar machen. Zugangsdaten in den Unraid-
Umgebungseinstellungen hinterlegen und nicht in das Repository einchecken.
