# Bundled data

## `dbip-country-lite.mmdb` — GeoIP (country level)

The GeoIP connector ([`pulse/connectors/geoip.py`](../connectors/geoip.py)) uses this file by default, so location lookups work offline and air-gapped with no setup.

- **Source:** DB-IP "IP to Country Lite", MMDB format — https://db-ip.com/db/download/ip-to-country-lite
- **Version:** September 2026 release (`database_type` `DBIP-Country-Lite`)
- **License:** [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). Redistribution is allowed with attribution.
- **Attribution:** "IP Geolocation by DB-IP" (https://db-ip.com). Pulse shows this link on every GeoIP result from a DB-IP database (the Investigate panel), as DB-IP requires for pages that display results.

**IP Geolocation by DB-IP** — https://db-ip.com

Why country and not city: the City Lite database is 127 MB, over GitHub's 100 MB file limit, and refreshing it monthly would add about 60 MB to the repository's history each time. For city-level detail, download DB-IP City Lite or MaxMind GeoLite2 City yourself and set its path under Settings › Notifications › GeoIP database (or `PULSE_GEOIP_DB`, or drop it in the top-level `data/` folder). Your file then takes priority over this one. MaxMind's GeoLite2 can't be bundled at all: its license forbids redistribution.

### Refreshing (monthly)

DB-IP publishes a new release at the start of each month.

```bash
curl -L -o /tmp/dbip.mmdb.gz https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz
gunzip -c /tmp/dbip.mmdb.gz > pulse/data/dbip-country-lite.mmdb
```

Update the version line above in the same commit.
