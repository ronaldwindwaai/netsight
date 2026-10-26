# Dev services

```sh
docker compose -f infrastructure/compose/docker-compose.dev.yml up -d postgres
```

Three roles exist (dev passwords, loopback only): `netsight` owns the schema and runs migrations,
`netsight_app` is the API's runtime role, `netsight_wan_collector` may only INSERT WAN samples.
Roles are created once, when the `pgdata` volume is new; after changing the init script run
`docker compose ... down -v` first.

Apply the schema and grants, then start the API on the least-privileged role:

```sh
cd apps/api
export DATABASE_MIGRATION_URL=postgresql://netsight:dev-only-change-me@127.0.0.1:5432/netsight
export DATABASE_APP_ROLE=netsight_app DATABASE_WAN_COLLECTOR_ROLE=netsight_wan_collector
uv run python -m netsight_api.storage.migrate up

export DATABASE_URL=postgresql://netsight_app:dev-only-app-change-me@127.0.0.1:5432/netsight
```
