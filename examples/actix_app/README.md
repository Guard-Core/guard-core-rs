# actix_app

Guarded actix-web service: the rate-limit and dynamic-ban stage installed as
an actix-web middleware (`Transform`), with every decision delegated to
[`guard_core_rs::tower`](https://github.com/Guard-Core/guard-core-rs)'s
`RateLimitStage::decide` so behavior is byte-identical to the tower stage.
All security decisions come from the engine stage; this example holds no
security logic beyond translating a block answer into an actix-web response
(the wiring an adapter performs).

## Routes

| Route | Stage | Behavior |
|---|---|---|
| `GET /health` | outside the guarded scope | `200 ok`, never throttled |
| `GET /` | guarded | `200` greeting, or the stage's block shapes |

Exclusion is expressed as routing (`/health` lives outside the wrapped
scope), the actix-web idiom for the reference engine's excluded paths.

## The stage

`src/stage.rs` is the centerpiece: a `RateLimitStageTransform`/`RateLimitStageService`
pair around any `Service<ServiceRequest>`. One request pass decides, exactly
as the tower stage's contract:

| Request state | Decision |
|---|---|
| no client IP | pass through |
| banned (no exemption skip) | `403 "IP address banned"` |
| over the rate limit (skipped for `is_whitelisted \|\| is_exempt`) | `429 "Too many requests"` + `Retry-After: <window>` |
| detection finding crosses a ban threshold (skipped for whitelisted, never exempt) | `403 "IP has been banned"` |
| everything else | pass through |

The client IP comes from the actix-web peer address (`req.peer_addr()`, the
spoof-proof source), falling back to the same forwarded-header policy the
tower default applies (leftmost `x-forwarded-for` entry, then `x-real-ip`).
The tower default extractor itself cannot be reused verbatim: actix-web 4
still speaks `http` 0.2 types on its public surface while the facade crate's
stage speaks `http` 1.x, so the policy is reimplemented over actix's types
and covered by the same tests. actix-web's own
`ConnectionInfo::realip_remote_addr` machinery is not consulted.

The skip state is an `IpGateDecision` request extension (what the global IP
gate leaves behind) and the detection result a `ThreatFinding` request
extension (what a prior detection stage inserts); bans and detection still
apply to an exempt IP. The trusted-proxies seam stays on the stage builder:
build the stage once with `RateLimitStage::builder(..).trusted_proxies(..)`
and hand it to the middleware.

## Running

```sh
cargo run -p guard-core-rs-actix-app
APP_ADDR=127.0.0.1:8080 cargo run -p guard-core-rs-actix-app
```

Quick manual check (default stage config throttles at 10 requests / 60 s):

```sh
for i in $(seq 1 12); do curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/; done
curl -is http://127.0.0.1:8080/health
```

## Tests

```sh
cargo test -p guard-core-rs-actix-app
```

Eight integration tests drive the installed middleware through actix-web's
test harness with the tower stage's fake-clock pattern: throttle shape +
window sliding + budget restore, `Retry-After` carrying the window, ban
answers first, exempt skip (bans still answering), default pass-through,
per-peer budgets, forwarded-header identity, and the auto-ban feed firing on
the crossing (429 first, 403 on the next request).
