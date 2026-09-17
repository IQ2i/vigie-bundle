# Multi-tenant: one CrowdSec instance for a whole portfolio

An agency running many small client sites — the setting Vigie was actually built for — can't reasonably
run one full CrowdSec instance (a LAPI, a database, an operator watching it) per client; most of these
sites don't produce enough traffic to justify one. The natural architecture is the opposite of
[doc/multi-server.md](multi-server.md): there, one application is replicated across several nodes that
must agree on shared state. Here, several *different* applications share one piece of infrastructure, and
must, for the most part, **not** agree on each other's data.

## One bouncer key per application, not per node

The same constraint [doc/threat.md](threat.md#operating-vigiethreatsync) already states — one CrowdSec
bouncer API key per consumer, because the LAPI keeps the delta cursor server-side, keyed by that API key
— applies here with "consumer" meaning a whole client application, not a node of one fleet. Run
`cscli bouncers add <client-slug>` once per client and give each application's own
`iq2i_vigie.threat.crowdsec.api_key` its own key. Nothing else in `threat.*` needs to differ between
clients.

## Acquisition: `service.name` already is the tenant

Every application already sets `iq2i_vigie.app` (`service.name` in the ECS document, see
[doc/siem.md](siem.md#field-mapping)) to identify itself. Point every client's `vigie.jsonl` at the same
CrowdSec instance — one `filenames` entry per file, or a glob, in the acquisition configuration — with
the same `type: vigie_ecs` label from [crowdsec/acquis/vigie.yaml.example](../crowdsec/acquis/vigie.yaml.example):
no per-client acquisition setup needed. The shared parser exposes this as `evt.Meta.tenant`, see
[crowdsec/parsers/s01-parse/vigie-ecs.yaml](../crowdsec/parsers/s01-parse/vigie-ecs.yaml).

## The cross-tenant leak: `username`/`session` scopes

- **`Ip`/`Range` decisions are safe to share, and sharing them is a feature.** An IP address means the
  same thing regardless of which client it hit: an address that brute-forced client A's login form gets
  banned for every other client behind the same LAPI too, real community defense across the whole
  portfolio, for free, with nothing to configure.
- **`username`/`session` decisions are not safe to share blindly.** These are "not CrowdSec constants",
  matched byte-for-byte on `value` (see [Scopes](threat.md#scopes)). Two client applications can easily
  both have a user named `admin`. A scenario reacting to client A's brute force by banning the `username`
  value `admin` would, on the same shared LAPI, also match client B's own `admin` account the next time
  client B's `ThreatCheckerInterface` looks it up — a decision meant for one client silently blocking a
  legitimate user of another.

### The fix

One config key on the read side, one scenario convention on the write side.

- **Reading a decision back:** set `threat.match.tenant_prefix` (default `null`, i.e. current
  single-tenant behavior; suggested value `%iq2i_vigie.app%`, since `iq2i_vigie.app` already is the
  tenant's own identity, see [Acquisition](#acquisition-servicename-already-is-the-tenant) above).
  `ThreatChecker` prefixes a `session`/`username` lookup with `<prefix>:` **after** `QueryNormalizer`/the
  HMAC, never before — a scenario can only ever see the already-HMACed `user.hash`/session id Vigie
  recorded, never the plain-text value, so prefixing before hashing would produce a HMAC of the prefixed
  string, which the scenario never wrote and can never match. `Ip`/`Range`/`Country`/`AS` decisions are
  never prefixed: sharing those across tenants is the feature described above, not the leak. See
  [doc/threat.md](threat.md#scopes) and [doc/configuration.md](configuration.md).
- **Writing a decision:** every user-keyed scenario's `groupby`/`distinct` (and, once one exists, its
  `scope.expression`) must key on `evt.Meta.tenant + ':' + evt.Meta.user_identifier` (or `.session_id`)
  instead of the bare identifier, matching the exact `<prefix>:` format above. One-line diff per scenario
  in [crowdsec/](../crowdsec):

  ```diff
  -groupby: "evt.Meta.user_identifier"
  +groupby: "evt.Meta.tenant + ':' + evt.Meta.user_identifier"
  ```

  and the same substitution inside `scope.expression`. This is on top of the `username` scope a LAPI
  profile must already produce for the value to reach a decision at all, see
  [crowdsec/profiles/vigie.yaml](../crowdsec/profiles/vigie.yaml) and
  [doc/threat.md](threat.md#scopes).
- **Pushing a decision (`threat.ingest`):** a decision pushed to the signed endpoint arrives with
  whatever `username`/`session` value the emitting SIEM chose. Vigie's ingest side does not, and cannot,
  guess a tenant: **prefixing is the emitter's responsibility**, the same `<prefix>:` format as above,
  before it signs and sends the payload.

### The write→store→match sequence

An activity carrying `userIdentifier: "alice"` is recorded with `record.user_identifier: hash` (or the
default `record.ip_address: anonymize` for the IP-keyed scenarios — irrelevant here): the ECS document
carries `user.hash`, an HMAC of `"alice"`, never the plain value. CrowdSec's parser exposes it as
`evt.Meta.user_identifier`, and `evt.Meta.tenant` as `service.name`. A tenant-aware scenario groups by
`evt.Meta.tenant + ':' + evt.Meta.user_identifier` and declares a `scope: {type: username, ...}` on the
same expression, so its alert's value is `"acme:<hash of alice>"`. The
[username profile](../crowdsec/profiles/vigie.yaml) routes that alert to a `username`-scoped decision,
inheriting the value verbatim. `vigie:threat:sync` (or `threat.ingest`, pushed by the emitter already
prefixed) pulls that decision into the local store unchanged: `"acme:<hash of alice>"`. On the next
request, `ThreatChecker` takes the raw `userIdentifier: "alice"` off `ThreatSubject`, runs it through
`QueryNormalizer` to get the same HMAC, then prefixes it with `threat.match.tenant_prefix` (resolved to
`"acme"` from `iq2i_vigie.app`) to get `"acme:<hash of alice>"` — byte-for-byte the value the decision
was stored under.

## Open question: one set of scenarios for the portfolio, or one per client?

A single, tenant-aware copy of each scenario (namespaced as above) serves every client from one CrowdSec
instance with one set of files to maintain, and lets an `Ip`/`Range` ban benefit every client
immediately. The alternative — a full, separate copy of [crowdsec/](../crowdsec) per client, isolated by
`threat.crowdsec.origins`/`scenarios_containing` (see [doc/configuration.md](configuration.md)) — trades
that shared maintenance for actual isolation: a misconfigured scenario for one client literally cannot
touch another client's decisions, at the cost of running every scenario once per client instead of once
for the whole portfolio.

Which one holds up in practice depends on how many clients the portfolio actually has and how much their
user bases can be trusted not to literally collide on identifiers. This page doesn't have a verified
answer: it's a description of the trade-off, not a recipe tested against a real multi-client fleet yet.
