# rocket_app

Guarded Rocket service: the rate-limit and dynamic-ban stage installed as a
request guard with its fairing and catchers, with every decision delegated to
[`guard_core_rs::tower`](https://github.com/Guard-Core/guard-core-rs)'s
`RateLimitStage::decide` so behavior is byte-identical to the tower stage.
All security decisions come from the engine stage; this example holds no
security logic beyond translating a block answer into a Rocket response (the
wiring an adapter performs).

## Routes

| Route | Guard | Behavior |
|---|---|---|
| `GET /health` | none | `200 ok`, never throttled |
| `GET /` | guarded | `200` greeting, or the stage's block shapes |

Exclusion is expressed as guarding (`/health` simply takes no guard
argument), the Rocket idiom for the reference engine's excluded paths.

## The stage

`src/stage.rs` is the centerpiece:

- `RateLimitFairing` attaches at ignite: it manages the
  `RateLimitStage` (the guard's source) and registers the `403`/`429`/`500`
  catchers.
- `RateLimitGuard` enforces: one `decide()` pass per request. Rocket guards
  cannot respond directly, so on a block the answer is stashed in
  request-local state and the guard's error outcome dispatches to the
  matching catcher, which renders the family shape (bare default body,
  `text/plain; charset=utf-8`, `Retry-After` on the throttled shape). This
  is the `rocket-guard-rs` adapter's fairing + guard + catcher pattern.

| Request state | Decision |
|---|---|
| no client IP | pass through |
| banned (no exemption skip) | `403 "IP address banned"` |
| over the rate limit (skipped for `is_whitelisted \|\| is_exempt`) | `429 "Too many requests"` + `Retry-After: <window>` |
| detection finding crosses a ban threshold (skipped for whitelisted, never exempt) | `403 "IP has been banned"` |
| everything else | pass through |

## Client IP extraction

The guard uses Rocket's own `Request::client_ip()` seam: the configured
`ip_header` value (`X-Real-IP` by default) when present and parseable, else
the remote peer address. Mind the posture difference from the tower default
(peer first): a direct-exposure deployment that keeps the default
`ip_header` lets any client spoof its throttling identity with a header, so
it should set `ip_header = ""` in Rocket config; a proxied deployment keeps
the header and strips it at the edge. The trusted-proxies seam that matters
for the ban engine's self-DoS refusal stays on the stage builder:
`RateLimitStage::builder(..).trusted_proxies(..)`.

The skip state is an `Option<IpGateDecision>` request-local cache entry
(what a global IP gate stage leaves behind) and the detection result an
`Option<ThreatFinding>` entry (what a prior detection stage inserts); bans
and detection still apply to an exempt IP. If the guard cannot find the
managed stage, the request is refused `500` (fail-secure), never passed
uninspected.

## Running

```sh
cargo run -p guard-core-rs-rocket-app
APP_ADDR=127.0.0.1:8081 cargo run -p guard-core-rs-rocket-app
```

Quick manual check (default stage config throttles at 10 requests / 60 s):

```sh
for i in $(seq 1 12); do curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/; done
curl -is http://127.0.0.1:8080/health
```

## Tests

```sh
cargo test -p guard-core-rs-rocket-app
```

Eight integration tests drive the guard and catchers through Rocket's local
asynchronous client with the tower stage's fake-clock pattern: throttle
shape + window sliding + budget restore, `Retry-After` carrying the window,
ban answers first, exempt skip (bans still answering), default pass-through,
remote-peer budgets, the `X-Real-IP` header winning the identity as Rocket
configures (with the malformed-header fallback to the remote), and the
auto-ban feed firing on the crossing (429 first, 403 on the next request).
