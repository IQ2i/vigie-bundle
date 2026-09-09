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

### The fix: namespace the value by tenant, on both sides

- **Writing a decision:** every scenario's `groupby`/`distinct` on a username or session must key on
  `evt.Meta.tenant + ':' + evt.Meta.user_identifier` (or `.session_id`), never the bare identifier, so a
  decision from two different tenants sharing a literal username never collides. This means adapting
  the six scenarios in [crowdsec/](../crowdsec) before running them this way: as shipped, only
  `vigie-login-bruteforce` and `vigie-credential-stuffing` key partly on IP already (safe), but their
  username component, and every other scenario's grouping, needs the tenant prefix added.
- **Reading a decision back:** `ThreatCheckerInterface` is queried with a plain `ThreatSubject`, built by
  `ThreatSubject::fromRequest()`/`::identity()`, or by hand. None of these know about a tenant prefix on
  their own. The application must prefix `userIdentifier`/`sessionId` with its own tenant slug before it
  reaches `ThreatSubject`, matching the exact prefix the scenario used to write the decision — a small
  wrapper around the value the token storage or the session hands back, at the one or two call sites that
  build a `ThreatSubject`, is the natural place; nothing in the bundle does this automatically, since it
  has no notion of "tenant" anywhere in its own model.

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
