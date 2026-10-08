# simple_app

Minimal guarded service: a tiny hand-rolled router wrapped in a guard shim
that runs the [`guard_core_rs::detect`](https://github.com/Guard-Core/guard-core-rs)
pipeline over every request, served over hyper. Every detection decision
comes from the engine; the example itself holds no security logic beyond
translating a verdict into a response (the wiring an adapter performs).

## Routes

| Route | Guard | Behavior |
|---|---|---|
| `GET /health` | excluded | `200 ok`, answered before the guard |
| `GET /` | guarded | `200`, greeting text |
| `GET /search?q=...` | guarded | `200 search ok`, or `400` when a query param trips the engine |
| `POST /echo` | guarded | echoes the request body; `400` for a threat, `413` over the body cap |
| anything else | guarded | `404 not found` |

The guard shim buffers the body, rejects over-cap bodies with `413` (the
default cap is the engine's `max_full_scan_bytes`, 262144 bytes), then scans
the URL path, each query parameter value, and the body with their reference
request contexts (`url_path`, `query_param`, `request_body`). A threat
verdict becomes `400` with the default block body.

`/health` demonstrates excluded-path behavior: the shim scans every request
it sees, so exclusion is expressed as routing (the branch runs before the
guard), the same effect the Python distro's excluded-paths configuration has.

## Running

```sh
docker compose -f examples/simple_app/docker-compose.yml up --build -d --wait
```

The compose stack builds the example from the repository root. Set
`SMOKE_PORT` to remap the host port. There is no Redis service:
guard-core-rs currently ships the CPU-bound detection pipeline only, with no
Redis, rate limit, or ban surface to wire up.

Run natively instead:

```sh
cargo build -p guard-core-rs-simple-app
APP_ADDR=127.0.0.1:8080 target/debug/guard-core-rs-simple-app
```

## Smoke assertions

The `live-smoke` GitHub Actions workflow runs exactly these against the
compose stack (on port 8080; set `SMOKE_PORT` to remap the host port):

| Assertion | Expected |
|---|---|
| `GET /` | `200` |
| `GET /health` | `200` (excluded path) |
| `GET /search?q=hello` | `200` |
| `GET /search?q=<script>alert(1)</script>` | `400`, body `{"detail":"Suspicious activity detected"}` |
| `GET /files/../../etc/passwd` (`--path-as-is`) | `400`, body `{"detail":"Suspicious activity detected"}` |
| `POST /echo` with a 300 KB body | `413`, body `{"detail":"Payload too large"}` (default cap: 262144 bytes) |
| `POST /echo` with body `hello world` | `200`, body echoed |

Quick manual check:

```sh
curl -is -G http://localhost:8080/search --data-urlencode 'q=<script>alert(1)</script>'
curl -is --path-as-is http://localhost:8080/files/../../etc/passwd
```

Tear down with:

```sh
docker compose -f examples/simple_app/docker-compose.yml down -v --remove-orphans
```
