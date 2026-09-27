# Configuration

There is no global config struct yet (the Python `SecurityConfig` section is
not ported). Detection is tuned through one flat struct,
`guard_core_rs::detect::DetectConfig`, passed to every `detect` call, the
global IP gate through `guard_core_engine::ip_gate::IpGateConfig`, and the
stateful layer (rate limiting, dynamic bans) through
`guard_core_engine::rate_limit::RateLimitConfig` and
`guard_core_engine::ip_ban::IpBanConfig`.

## IpGateConfig (whitelist / blacklist / exempt_ips)

The global IP gate is the Rust family's minimal port of the reference
engine's global IP stage. Build it once at startup with
`IpGateConfig::new(whitelist, blacklist, exempt_ips)`, which fails closed on
an invalid entry, and evaluate request IPs with `IpGateConfig::evaluate`:

| List | Semantics |
|---|---|
| `whitelist` | Allowlist. When non-empty, every IP it does not match is denied (`IP not in whitelist`) |
| `blacklist` | Denylist, consulted when `whitelist` is empty (`IP is blacklisted`) |
| `exempt_ips` | Skip-list for known-friendly automation; sets the skip flag, never a deny path |

Matching semantics are identical for all three lists, mirroring the reference
whitelist matcher: a bare IP or a CIDR range (host bits cleared at parse
time), IPv4-mapped forms matched against their IPv4 canonical form
(`::ffff:203.0.113.7` matches `203.0.113.7` and `203.0.113.0/24`), and no
cross-family matching.

### exempt_ips vs whitelist

`exempt_ips` is noise reduction for known-friendly automation (monitoring
probes, VPN egress, a partner's server), not immunity: it is noise reduction
for known-friendly automation, not immunity; the blacklist, dynamic bans,
route rules and detection still apply. An exempt match sets the same skip
state a whitelist match sets (`IpGateDecision::is_exempt`) but never adds a
deny path of its own and never opens the whitelist gate: with a restrictive
whitelist, an exempt IP that is not itself whitelisted is still denied. The
stateful stages below (rate limiting, violation counting, dynamic bans) skip
exactly what the reference skips for a whitelist match
(`is_whitelisted || is_exempt`) and never skip penetration detection; the
user-agent filter below follows the same rule.

## Rate limiting (rate_limit)

The sliding-window rate limiter mirrors the reference engine's rate
limiter in its in-memory mode (the reference falls back to this exact store
when Redis is off; the Redis-distributed mode is a follow-up).

`RateLimitConfig` carries the knobs:

| Field | Type | Default | Reference knob |
|---|---|---|---|
| `enable_rate_limiting` | `bool` | `true` | `enable_rate_limiting` |
| `rate_limit` | `u32` | `10` | `rate_limit` (requests per window, >= 1) |
| `rate_limit_window` | `u64` | `60` | `rate_limit_window` (seconds, >= 1) |
| `enable_rate_limit_auto_ban` | `bool` | `false` | `enable_rate_limit_auto_ban` |
| `endpoint_rate_limits` | `HashMap<String, RateLimitEntry>` | empty | `endpoint_rate_limits` (per-endpoint `(requests, window)` tier) |

The config constructor fails closed on a zero limit or window (Python's
pydantic rejects them with `ge=1`) and on any `endpoint_rate_limits` entry
with a zero `requests` or `window`, the same bound the tier entries
inherit. `RateLimitEntry::new` and `RouteRateLimits::new` carry the same
fail-closed validation for the tier overrides.

Counting semantics: one sliding log of request timestamps per
`(client IP, scope)`. Before a request is recorded, every timestamp at or
before `now - window` is evicted; the pre-recording count decides
(`allowed = count < rate_limit`), and the block reports
`count + 1` (the current request included), exactly the reference's
in-memory formulation. The Redis formulation (`allowed = count <= limit`
over the post-recording rank) draws the same boundary. A blocked caller
retries after the window (`Retry-After: <window seconds>`, the reference's
`429 Too many requests` shape). The window store is an LRU capped at 10 000
keys (`_MAX_TRACKED_RATE_LIMIT_KEYS`).

Scope: `check(ip, None)` is the global per-IP window (the default pipeline
tier, every endpoint sharing one budget); `check(ip, Some(path))` is the
per-endpoint window keyed by `(ip, path)` (the reference's
`endpoint_path`-keyed tier).

### Rate-limit tiers (`check_tiers`)

`check_tiers(ip, url_path, route, country_of_ip)` runs the reference
pipeline's tier order (`RateLimitCheck.check` in `rate_limit.py`, via the
Go port's `tiersFor`/`runTier`). Every configured tier records one hit
into its own `(ip, path)` window (each tier is an independent budget,
exactly as the references count), and the first tier that crosses decides
the outcome with its own window for `Retry-After`:

1. **endpoint** - `endpoint_rate_limits[url_path]` (exact path match);
2. **route** - the decorator's `rate_limit` (window default 60,
   `rate_limit_window or 60`);
3. **geo** - the decorator's `geo_rate_limits`: the resolved country's
   entry with the `"*"` fallback (`country in limits else "*" in limits`).
   Without a country resolver the tier never applies (the reference's
   `if not geo_handler: return None`), even with a `"*"` entry;
4. **global** - the flat `rate_limit`/`rate_limit_window`, keyed by IP
   alone.

Without any tier configured the sequence collapses to the global tier:
byte-identical to the pre-tier behavior. `RouteRateLimits` is the validated
carrier for the decorator tiers (`None` fields inherit or skip). The
references always key the route and geo tiers by the request path, so a
call without a `url_path` runs the global tier only.

## Dynamic IP bans and the auto-ban engine (ip_ban)

The ban store mirrors the reference `IPBanManager` in its in-memory mode:

- `ban_ip(ip, duration, reason)` records `expiry = now + duration`; a
  duration of zero is rejected (`BanError::NonPositiveDuration`, the
  reference raises). Re-banning a live IP overwrites its record.
- Durations beyond `LOCAL_CACHE_TTL_CAP_SECONDS` (3600) are clamped to it,
  the references' local-store cap (`clampToLocalCap`, cause
  `not configured`, and the Python `TTLCache(ttl=3600)`); only the Redis
  backend honors longer bans. The default `auto_ban_duration` sits exactly
  at the cap.
- `is_banned(ip)` honors expiry with the Go boundary: an IP is banned while
  `now <= expiry`; strictly past it the entry reads unbanned and is dropped.
- The store is an LRU capped at 10 000 entries (silent overflow, the
  references' `localCacheMaxSize` / `maxsize=10000`).
- Self-ban refusal: loopback (`127.0.0.0/8`, `::1/128`) and configured
  trusted-proxy targets return `Ok(false)` and record nothing - the
  references' self-DoS guard. Trusted proxies parse fail closed
  (`IpBanManager::with_trusted_proxies`).
- IPv4-mapped addresses canonicalize to their IPv4 form before any store
  key, so `::ffff:203.0.113.7` and `203.0.113.7` share buckets, bans, and
  counters.

`IpBanConfig` carries the auto-ban knobs:

| Field | Type | Default | Reference knob |
|---|---|---|---|
| `enable_ip_banning` | `bool` | `false` | `enable_ip_banning` |
| `auto_ban_threshold` | `u32` | `10` | `auto_ban_threshold` (>= 1) |
| `auto_ban_duration` | `u64` | `3600` | `auto_ban_duration` (seconds, >= 1) |
| `threat_ban_config` | map of category to `ThreatBanEntry { threshold, duration }` | empty | `threat_ban_config` |

Category keys are validated at config time (fail closed, like
`IpGateConfig`): a key must be a pattern-table detection category or the
`rate_limit` pseudo-category (`valid_threat_categories()`), the reference's
`ALL_DETECTION_CATEGORIES | {'rate_limit'}` set. Unknown keys are rejected,
as in Python and the TypeScript port.

Violation counting and threshold resolution mirror
`_resolve_and_apply_threshold_ban` (the TypeScript `resolveThresholdBan`):
`ViolationCounters` accumulates per IP per category (LRU capped at 10 000
IPs, `_MAX_TRACKED_SUSPICIOUS_IPS`; an empty category list records
`uncategorized`), and `IpBanManager::register_violations` (or the pure
`resolve_threshold_ban`) resolves in the reference's order:

1. banning disabled: no ban (violations still count, so enabling banning
   later starts from observed history);
2. the first listed category whose `threat_ban_config` entry's threshold is
   met (`count >= threshold`) bans with that entry's duration and reason
   `"<reason>:<category>"`;
3. otherwise the flat threshold, measured against the total of all counted
   categories, bans with `auto_ban_duration` and the plain reason;
4. the self-DoS guard can refuse the resulting ban.

The rate-limit pseudo-category feeds the same engine when
`enable_rate_limit_auto_ban` is on: a rate-limit crossing counts as one
`rate_limit` violation, so `threat_ban_config["rate_limit"]` overrides and
the flat threshold backs it up (reason `rate_limit_exceeded`), exactly the
reference pipeline's behavior.

## DetectConfig

| Field | Type | Corpus default | Notes |
|---|---|---|---|
| `max_content_length` | `usize` | `10000` | `detection_max_content_length`: the semantic budget; the processed content is truncated to this many code points before analysis, and it bounds truncation |
| `max_full_scan_bytes` | `usize` | `262144` | `detection_max_body_inspect_bytes`: the preprocessor's full-scan cap; content beyond it is handled by the attack-preserving truncation path |
| `preserve_attack_patterns` | `bool` | `true` | `detection_preserve_attack_patterns`: keep attack-relevant regions intact across the decode pipeline |
| `semantic_threshold` | `f64` | `0.7` | `detection_semantic_threshold`: per-attack-type semantic threats fire at or above this probability |
| `threat_score_threshold` | `f64` | `1.0` | `detection_threat_score_threshold`: the regex-anomaly weight sum at or above which the verdict is a threat |

## Scoring semantics

`is_threat` is `sum(regex weights) >= threat_score_threshold` or any semantic
threat. `threat_score` is `min(max(regex anomaly, semantic max), 1.0)` when
any threat exists, else `0.0`. Semantic threats are emitted per attack type
at or above `semantic_threshold`, with a `suspicious` fallback carrying the
overall score when no individual type crosses the line.

## Request contexts

`detect(content, request_context, config)` normalizes the context (the part
before the first `:`) to one of `query_param`, `header`, `url_path`,
`request_body`, or `unknown`. Unknown contexts relax the pattern view
filters; embedded-JSON leaf contexts (a `:embedded_json` suffix) keep the
suffix for validator scoping.

## Per-route detection exclusions (detection_exclusions)

The per-request detection exclusion resolution and the multi-surface
request scan mirror `guard_core/_utils/detection_config.py` and the
pipeline's `detectThreat` (via the Go port's `detectionexclusions.go`). The
decision core is `guard_core_engine::detection_exclusions::scan_request`;
adapters resolve `Some(&DetectionExclusionConfig), Some(&route)` per request
(the route standing in for `request.state.route_config`) and translate the
`RequestScanVerdict` into the pipeline's `ThreatFinding`.

Resolution (`resolve`), the reference `_resolve_*` semantics:

| Surface | Route `None` | Route `Some` |
|---|---|---|
| `excluded_detection_headers` | defaults + config | merged: defaults + config + route (additive, never a replacement) |
| `excluded_detection_params` | config | route replaces |
| `excluded_detection_body_fields` | config | route replaces |
| `enabled_detection_categories` | config (`None` = every category) | route replaces (an empty set disables every category) |
| `detection_scan_body` | config (`None` = `true`) | route overrides both directions |

All sets lowercase at resolution time, so matching is case-insensitive.

Scan order (`scan_request`): URL path (`url_path`), query params skipping
excluded names (`query_param`), headers (`header`; an excluded header is
not skipped outright - it scans with its known-false-positive categories
suppressed, `ssrf` for the address-carrying proxy headers and for
whole-address-chain values, so a payload in the same header still
detects), then the body surface when `scan_body` is set (form pairs,
multipart parts, JSON walks, and the blob fallback, each honoring the
excluded body fields). A value that is a threat but whose categories are
all filtered out ends the scan clean - the reference's per-value filter is
terminal, not a reason to keep scanning later values. Regex threats carry
the category; semantic threats carry none (the reference's semantic
payloads have no `category` key). Mongo-operator JSON keys
(`$where`, `$ne`, ...) hit from the walk unfiltered by the category set.

Route toggles: `detection_enabled(global, route)` applies the route's
`enable_suspicious_detection` over the global `enable_penetration_detection`
in both directions at request time, and `check_applies` keeps the
suspicious-activity check alive while the global flag is on or any route
enables its toggle (the reference `SuspiciousActivityCheck.applies_to`).

## Request size and content-type limits (request_limits)

The route-scoped size and content gate mirrors the reference engine's
`request_size_content` check
(`guard_core/core/checks/implementations/request_size_content.py`). The
decision core is `guard_core_engine::request_limits::decide`; the tower stage
is `guard_core_rs::request_limits::RequestLimitsStageLayer`.

Both limits are route config in the reference (`RouteConfig.max_request_size`,
`RouteConfig.allowed_content_types`); there is no global knob, so the Rust
`ContentLimits` carries both as `Option` and the all-`None` default is inert:

| Field | Type | Default | Reference knob |
|---|---|---|---|
| `max_request_size` | `Option<u64>` | `None` | `RouteConfig.max_request_size` (bytes) |
| `allowed_content_types` | `Option<Vec<String>>` | `None` | `RouteConfig.allowed_content_types` |

Behavior, in the reference's order:

- **Size first**: a missing or empty `content-length` header passes; a value
  at or under the limit passes; one over answers `413 "Request too large"`
  (reason `Request size {n} exceeds limit: {max}`). The parse mirrors
  Python's `int()`: surrounding whitespace and a leading sign are accepted,
  and a negative value passes (`-1 <= limit`).
- **Then the media type**: the exact prefix before the first `;` (no trim,
  case-sensitive) must be in `allowed_content_types`, else
  `415 "Unsupported content type"`. A missing `content-type` header compares
  as the empty string and is blocked by any non-empty allowed list, exactly
  as in Python.
- **Fail-secure**: a non-integer `content-length` header mirrors the
  reference's `int()` `ValueError`: `decide` returns `Err`, and the tower
  service answers the pipeline's fail-secure shape
  `500 "Security check failed"` (`fail_secure = True` default).

The stage learns a path's limits through a `RouteLimitsResolver`
(`path -> Option<ContentLimits>`, the tower counterpart of the reference's
`request.state.route_config`); an unconfigured path passes.

Not mirrored: the reference's `EVENT_CONTENT_FILTERED` events, `log_activity`
entries, `passive_mode` (no Rust config surface yet), the `on_block` hook,
and `custom_error_responses` body overrides. The decision core returns the
reference reason strings for adapters that log.
## Blocked user agents (user_agent)

The user-agent filter mirrors the reference engine's `user_agent` check
(`guard_core/core/checks/implementations/user_agent.py`) and its matcher
(`_user_agent_matches_blocked_pattern` / `is_user_agent_allowed`). The
decision core is `guard_core_engine::user_agent::UserAgentFilter`; the tower
stage is `guard_core_rs::user_agent::UserAgentStageLayer`.

The config knob is the reference `blocked_user_agents` list, where every
entry is a regular expression:

| Field | Type | Default | Reference knob |
|---|---|---|---|
| `UserAgentStageConfig.blocked_user_agents` | `UserAgentFilter` (compiled `blocked_user_agents`) | empty, never blocks | `SecurityConfig.blocked_user_agents` |
| `UserAgentStageConfig.ip_ban` | `IpBanConfig` | off | `enable_ip_banning` + thresholds |

Behavior:

- **Matching**: the `User-Agent` header value is truncated to its first 512
  code points (`_MAX_USER_AGENT_MATCH_LENGTH`) and tested against every
  pattern with search semantics under the reference compiler's
  case-insensitive + multiline flags; any match blocks. A missing header
  reads as the empty string.
- **Validation**: `UserAgentFilter::new` fails closed on a pattern the ReDoS
  validator rejects (`_validate_blocked_user_agents_value` raises the same
  way) and, diverging earlier, on a pattern the regex engine cannot compile
  (the reference would raise at request time and trip the fail-secure 500).
- **Skip state**: the stage passes for `is_whitelisted \|\| is_exempt`, read
  from an `IpGateDecision` request extension.
- **Route lists**: the reference tries `route_config.blocked_user_agents`
  before the global list; the builder's `routes` seam resolves a path to a
  compiled per-route filter (same route seam as `request_limits`).
- **The block shape**: `403 "User-Agent not allowed"`, answered even without
  a client IP.
- **The ban feed**: a block runs the reference's
  `escalate_identity_violation` shape - only a `ThreatFinding` request
  extension marked `is_threat` counts (empty categories record
  `uncategorized`), feeding `register_violations` under reason
  `Blocked user agent: <truncated user agent>` with the stage's
  `IpBanConfig`. The 403 goes out either way; the ban answers the next
  request. The builder's `ban_engine` seam shares the
  `IpBanManager`/`ViolationCounters` pair with the rate-limit stage (the
  reference's module-singleton); without it the stage holds a private pair.

Not mirrored: `log_activity`/event emissions, `passive_mode` (no Rust config
surface yet), and the `log_sensitive_*` redaction of the user agent in
reasons.

## The tower stage (guard_core_rs::tower)

The facade crate carries the first pipeline stage: a `tower::Layer`
(`RateLimitStageLayer`) for Axum/tonic-shaped stacks that wires the stateful
modules above into one request pass, mirroring the reference pipeline's
behavior for the two checks the stage owns (`rate_limit`, the ban check of
`ip_security`, and the detection feed of `suspicious_activity`):

| Request state | Decision |
|---|---|
| no client IP | pass through |
| banned (no exemption skip) | `403 "IP address banned"` |
| over the rate limit (skipped for `is_whitelisted \|\| is_exempt`) | `429 "Too many requests"` + `Retry-After: <window>` |
| detection finding crosses a ban threshold (skipped for whitelisted, never exempt) | `403 "IP has been banned"` |
| everything else | pass through |

- The client IP comes from the `SocketAddr` request extension (the peer
  address), falling back to the leftmost `x-forwarded-for` entry, then
  `x-real-ip`; a custom extractor replaces the default policy.
- The skip state is an `IpGateDecision` request extension, exactly what the
  global IP gate leaves behind; bans and detection still apply to an exempt
  IP.
- A crossing feeds `register_violations` with the `rate_limit`
  pseudo-category (reason `rate_limit_exceeded`) when
  `enable_rate_limit_auto_ban` is on; the `429` still goes out and the ban
  answers the next request, as in the reference.
- A `ThreatFinding` request extension (what a prior detection stage
  inserts) feeds the same engine with its categories (reason
  `penetration_attempt`); the crossing request itself is answered with the
  403 crossing-ban shape.
- The stage config is the pair of stateful configs above
  (`RateLimitStageConfig { rate_limit, ip_ban }`); construction fails
  closed on any invalid part (rate limit bounds, trusted-proxy entries,
  ban-config validation).
- **Rate-limit tiers**: the service resolves the request path
  (`request.uri().path()`) and the tier surfaces ride alongside it. The
  endpoint tier is the config's `endpoint_rate_limits` map; the decorator
  tiers arrive either as a `RouteRateLimits` request extension (what an
  adapter's routing layer inserts) or through the builder's
  `route_resolver` seam (`path -> Option<RouteRateLimits>`, the same
  route seam the request-limits and user-agent stages use; an explicit
  extension wins). The geo tier resolves its country through the builder's
  `geo_handler` seam (`Arc<dyn GeoIpHandler>`); without a handler it never
  applies. A tier crossing answers the same `429` shape with the blocking
  tier's window and feeds the auto-ban engine exactly as the global tier
  does. With no tiers configured the stage is byte-identical to the
  pre-tier global-only behavior.
- Not mirrored: the reference's per-tier event emissions and reason
  strings (`EVENT_DECORATOR_VIOLATION` payloads; the decision names the
  tier instead), `log_activity`, and the suspicious-activity
  `400` answer for a threat below the ban threshold (the detection stage
  has no tower counterpart yet).

## The actix-web and rocket example stages (examples/)

The same stage ships wired for two more frameworks as example workspace
members, reusing `RateLimitStage::decide()` as the single decision point so
the family shapes are byte-identical to the tower stage. Both hold no
security logic of their own; the translation from native request types to
`decide()` inputs and back is the wiring an adapter performs.

- `examples/actix_app` (`src/stage.rs`): an actix-web `Transform`
  middleware (`RateLimitStageTransform`) installed with `App::wrap` or
  `Scope::wrap`. The client IP comes from the peer address
  (`req.peer_addr()`), falling back to the tower default's forwarded-header
  policy (leftmost `x-forwarded-for`, then `x-real-ip`) reimplemented over
  actix's types: actix-web 4 still speaks `http` 0.2 on its public surface
  while the facade stage speaks `http` 1.x, so the tower default extractor
  cannot be reused verbatim. actix-web's own
  `ConnectionInfo::realip_remote_addr` machinery is not consulted.
- `examples/rocket_app` (`src/stage.rs`): a request guard
  (`RateLimitGuard`) plus ignite fairing plus scoped catchers, the
  `rocket-guard-rs` adapter's pattern. Rocket guards cannot respond
  directly, so the block answer is stashed in request-local state and the
  error outcome dispatches to the matching catcher, which renders the
  family shape. The client IP comes from Rocket's own `client_ip()` seam:
  the configured `ip_header` (`X-Real-IP` by default) when present and
  parseable, else the remote peer. Mind the posture difference from the
  tower default (peer first): a direct-exposure deployment should set
  `ip_header = ""` so a client-supplied header cannot spoof its throttling
  identity. A request arriving while the managed stage is absent is refused
  `500` (fail-secure), never passed uninspected.

In both stages the skip state (`is_whitelisted`, `is_exempt`) and the
detection result arrive exactly as in tower (an `IpGateDecision` and a
`ThreatFinding`, in request extensions or request-local cache entries
respectively), and the trusted-proxies seam stays on the stage builder
(`RateLimitStage::builder(..).trusted_proxies(..)`).

## What is not implemented (fail-closed honesty)

The port targets spec 4.0.2 and is not complete. Do not expect these yet:

- **The 4.x pattern-table scan stage**: the full reference regex table
  across all scan views has no Rust counterpart yet; the corpus xfail
  baseline records the resulting divergences (the dominant cause of xfail
  entries).
- **Config, pipeline, and handler sections** (Python sections 02, 03,
  07-12): no `SecurityConfig`, no middleware protocol, no handlers,
  protocols, or decorators. The global IP gate (`whitelist`, `blacklist`,
  `exempt_ips`) exists (`ip_gate`), the in-memory rate limiter and dynamic
  IP ban store exist (`rate_limit`, `ip_ban`), the rate-limit/ban
  pipeline stage exists for tower stacks (`guard_core_rs::tower`) and as
  example wirings for actix-web and Rocket (`examples/actix_app`,
  `examples/rocket_app`), and the route-scoped request size/content gate
  exists (`request_limits`), but there
  is no Redis-backed distributed mode, no cloud provider blocking, no
  user-agent filtering, and no response factory; the remaining pipeline
  `examples/rocket_app`), and the user-agent filter exists (`user_agent`),
  but there
  is no Redis-backed distributed mode, no cloud provider blocking, and no
  response factory; the remaining pipeline
  stages and the published framework adapters live in the adapter repos.
- **`PerformanceMonitor`** and per-scan timeouts, plus a handful of tracked
  detection knobs recorded as unmapped with reasons.

## Conformance knobs

The conformance harness maps the five `DetectConfig` fields above from the
corpus `config_knobs` and records every unmapped knob with a reason. Changing
engine behavior requires the ledger or xfail baseline to stay consistent:
the gate fails on unbaselined failures, stale xfails, and not-run corpus
cases alike.
