# Multi-server deployments

A fleet of identical Symfony application servers behind a load balancer, all feeding one shared SIEM,
breaks two assumptions a single-server setup gets for free: that a visitor's activity lands in one place,
and that "the log" is one file someone can `tail`. This page collects what to check before relying on
Vigie's output across such a fleet, and the two ways to get it to a central collector without shipping a
log file around. This is one application replicated across several nodes, all agreeing on shared state; for
several *different* applications sharing one CrowdSec instance instead (an agency's portfolio of client
sites), see [doc/multi-tenant.md](multi-tenant.md).

## What ties a visitor's activity together across nodes

These are the fields [doc/recording.md](recording.md) and [doc/siem.md](siem.md) already describe, read
with a fleet in mind:

- `user.name` / `user.hash`: the strongest signal, present on every authenticated action regardless of
  which node served it.
- `vigie.session_id`: stable across nodes only if sessions themselves are shared (Redis, a database
  session handler). With sticky sessions and a local session store, the same visitor gets a different
  session id on every node it fails over to, and a scenario counting distinct sessions overcounts. If
  sessions are shared, `vigie.session_id` already correlates.
- `source.ip`: only as good as `framework.trusted_proxies` (see below).
- `http.request.id`: correlates the lines one node produced for one request. See
  [Request ids across the load balancer](#request-ids-across-the-load-balancer) to extend that across the
  load balancer's own logs.
- `host.hostname`: which node produced the line at all. See [Telling nodes apart](#telling-nodes-apart)
  below.

None of this works if the fleet doesn't agree on one thing first.

## The HMAC secret must be identical on every node

`vigie.session_id` and a hashed `user.hash` (`record.user_identifier: hash`) are both
`hash_hmac('sha256', $value, $secret)`, keyed by `record.hash_secret`, which defaults to
`%kernel.secret%` (`APP_SECRET`). If one node runs with a different secret than the rest of the fleet, a
stale deploy or an environment file that didn't propagate, the same session or the same user hashes to a
different value on that node. There is no error: the lines are all individually valid, correlation just
quietly stops working across that one node. Roll `APP_SECRET` (or `record.hash_secret`) on every node at
once; a staggered rotation has the same effect as a misconfigured node until it finishes.

## `framework.trusted_proxies`

Already covered in [doc/recording.md](recording.md#what-gets-recorded) and
[The pseudonymization pitfall](threat.md#the-pseudonymization-pitfall). Set it correctly, or
`source.address` is the load balancer's own IP on every line, from every node, and every visitor behind it
is indistinguishable.

## Request ids across the load balancer

`http.request_id_header` (see [doc/configuration.md](configuration.md)) trusts an inbound header as the
request id instead of minting a fresh UUIDv7. Have the load balancer generate and set it, nginx for
instance:

```nginx
proxy_set_header X-Request-Id $request_id;
```

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    http:
        request_id_header: 'X-Request-Id'
```

One client request now carries the same id through the load balancer's own access log and the Vigie line
of whichever node served it, joining "which node handled this" with "what did the edge see".

## Telling nodes apart

Nothing in the ECS output said which server emitted a line before this: `service.name`/`service.environment`
(`iq2i_vigie.app`/`env`) identify the application, not the node running it. `iq2i_vigie.hostname` adds
`host.hostname`:

```yaml
iq2i_vigie:
    hostname: true   # the default, see below
```

- `true` (the default) resolves `gethostname()` at runtime, the first time an activity is recorded, never
  at container compile time. A compiled container is typically built once (CI, a Docker image) and shipped
  identically to every node of the fleet, so resolving it at compile time would stamp every node's line
  with the build machine's hostname instead of the node's own.
- A string sets it explicitly: an env placeholder for a container whose own `gethostname()` is a
  throwaway id rather than a stable node name, `hostname: '%env(HOSTNAME)%'`.
- `false` omits `host.hostname` entirely, for a stream that leaves your infrastructure (a managed SIEM, a
  third party), where a server naming convention has no business being disclosed.

Monolog's own `SyslogHandler`/`SyslogUdpHandler` stamp their syslog header with `gethostname()`
independently of this option (see [Sending to syslog](#sending-to-syslog) below). If `hostname` is set to
an explicit string that differs from the machine's real name, the syslog header and `host.hostname` in the
JSON body can disagree. Treat `host.hostname` in the JSON body as authoritative: it's the value Vigie was
told to use.

## Clock drift

`@timestamp` (`occurredAt`) and `event.created` (`recordedAt`) both come from each node's own clock. Without
NTP kept in sync across the fleet, a SIEM sorting by `@timestamp` interleaves nodes incorrectly, and a
narrow-window correlation ("a login immediately followed by an export") can appear to run backwards.
`event.id` (a UUIDv7) stays a reliable dedup/ordering key even when timestamps drift, since it's minted
in-process at record time rather than read back from the clock.

## Sending to syslog

The default storage writes NDJSON to a file (`iq2i_vigie.output.path`), fine on one server, but a fleet of
N nodes then means N files to collect, one per node, usually with a log shipper (filebeat, vector, an
rsync job) installed just for that. See [doc/storage.md](storage.md#sending-to-syslog) for the base setup:
`iq2i_vigie.output.handlers` accepts any Monolog handler, and Monolog ships syslog handlers.

Two topologies:

### A. Local syslog, relayed by rsyslog (recommended)

Configure `Monolog\Handler\SyslogHandler` as shown in
[doc/storage.md](storage.md#sending-to-syslog). PHP writes to the machine's local syslog
(`syslog(3)`), and the node's own rsyslog relays it onward, over TCP or RELP, with a disk-backed queue
that survives a restart or a network blip. Nothing here is Vigie-specific to validate on your own
infrastructure; a starting point:

```
# /etc/rsyslog.d/30-vigie.conf, indicative: validate against your own rsyslog version and infra
template(name="VigieRaw" type="string" string="%msg:2:$%\n")

if ($syslogtag startswith 'vigie') then {
    action(type="omfwd" target="collector.internal" port="6514" protocol="tcp"
           template="VigieRaw"
           queue.type="linkedlist" queue.filename="vigie_fwd"
           queue.saveOnShutdown="on" action.resumeRetryCount="-1")
    stop
}
```

`%msg:2:$%` strips rsyslog's own leading space and keeps only the MSG part, the JSON line Vigie wrote, with
no syslog header glued to it. The collector then acquires exactly the NDJSON [doc/storage.md](storage.md)
already documents, so the existing CrowdSec `filenames` acquisition and `vigie-ecs` parser from
[doc/siem.md](siem.md#crowdsec-acquisition) apply unchanged. No message-size limit, no dropped datagrams:
the queue is what makes this durable where UDP (topology B) isn't.

### B. Direct UDP to a remote collector

```yaml
# config/services.yaml
services:
    app.vigie.syslog_handler:
        class: Monolog\Handler\SyslogUdpHandler
        arguments:
            $host: '%env(VIGIE_SYSLOG_HOST)%'
            $port: 514
            $facility: 'local0'
            $ident: 'vigie'
            $maxLength: 1024  # Monolog otherwise defaults to the theoretical UDP maximum,
                               # which routers and firewalls along the way silently truncate or drop
        calls:
            - setFormatter: ['@iq2i_vigie.formatter.ecs.syslog']
```

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    output:
        handlers: ['app.vigie.syslog_handler']
```

PHP sends RFC-framed UDP datagrams straight to a remote syslog server, CrowdSec's own `syslog` datasource
for instance:

```yaml
# /etc/crowdsec/acquis.d/vigie.yaml
source: syslog
listen_addr: 0.0.0.0
listen_port: 514
labels:
  type: vigie_ecs
```

Simpler, one moving part and nothing to run on the node beyond PHP itself, but be aware of what CrowdSec's
own documentation says about this datasource: UDP only, a default `max_message_len` of 2048 bytes, and a
real risk of dropping messages past a few hundred events per second, with rsyslog plus a file acquisition
(topology A) recommended for anything beyond a small deployment. `$maxLength` above caps what Vigie itself
sends, but a datagram that exceeds it is truncated, not split, and a truncated ECS line is no longer valid
JSON. See [Keeping a line under 2048 bytes](#keeping-a-line-under-2048-bytes) before choosing this topology
for anything beyond a proof of concept.

Sending UDP requires the `sockets` PHP extension. Monolog's `SyslogUdpHandler` checks for it when the
handler is first instantiated (the first recorded activity), not at container compile time.

### The CrowdSec parser, either way

The `vigie-ecs` parser in [doc/siem.md](siem.md#crowdsec-acquisition) is written against a plain NDJSON
file: `evt.Line.Raw` is exactly one JSON document. With topology A that stays true, since rsyslog already
stripped its own header before writing the file CrowdSec acquires. With topology B, whether the syslog
datasource hands the parser the JSON alone or the JSON still wrapped in a syslog header is a detail of the
CrowdSec version in use, verify it against your own instance before relying on the existing parser
unchanged. A `JsonExtract` failing silently (every `parsed` field empty, no error logged) is the symptom of
a header still attached. This is also an argument for preferring topology A outright: it sidesteps the
question entirely.

## Keeping a line under 2048 bytes

Only relevant for topology B above. `record.*` redaction is global (see
[doc/storage.md](storage.md#the-default-monolog-storage)), narrowing it to fit one transport narrows the
file output too, so weigh that before reaching for these:

- `record.context: false`, usually the single biggest contributor: `vigie.context` is unbounded, and so is
  anything `route_params` copies into it.
- `record.route_params: false` (already the default).
- `record.user_agent: false`: a modern user agent string easily runs 100-200 bytes on its own.
- `record.query_string: false` (already the default): leave it off.
- `record.uri: false` as a last resort.

Narrowing `http.recorded_paths` to only what actually needs recording reduces volume, which matters more
for topology B's "a few hundred events per second" ceiling than line size does.

## Threat decisions in a fleet

The activity stream above only leaves each node: nothing on that side needs a fleet-wide store. The return
path (reading back a SIEM's decisions, [doc/threat.md](threat.md)) is the opposite: every node enforcing a
decision needs to see the same one, and that requires a deliberate setup.

### The one thing that's mandatory: a shared `threat.cache.pool`

`iq2i_vigie.threat.storage: cache` (the default) backs decisions with `iq2i_vigie.threat.cache.pool`,
`cache.app` by default, usually a cache local to whichever node writes or reads it. In a fleet, that's
broken by construction: whichever node runs `vigie:threat:sync` writes into its own local cache, and a
node enforcing decisions reads from its own, unrelated one. `ThreatEnforcementSubscriber` never blocks
anything on any node that isn't the one that happened to sync, silently.

Point `threat.cache.pool` at a backend every node actually shares, Redis, reusing the same instance already
recommended for shared sessions:

```yaml
# config/packages/cache.yaml, identical on every node
framework:
    cache:
        default_redis_provider: '%env(REDIS_DSN)%'
        pools:
            vigie.threat_cache:
                adapter: cache.adapter.redis
```

```yaml
# config/packages/vigie.yaml, identical on every node
iq2i_vigie:
    threat:
        enabled: true
        provider: crowdsec
        cache:
            pool: 'vigie.threat_cache'
        crowdsec:
            api_key: '%env(CROWDSEC_API_KEY)%'
```

Deploy the exact same `iq2i_vigie` configuration to every node, including the nodes that never run
`vigie:threat:sync` themselves. `threat.provider`/`threat.crowdsec.api_key` sit unused on a node that only
serves HTTP requests and enforces decisions, since only the CLI command ever calls `pull()`. There's
nothing to diverge per node; what differs is which servers actually run the cron, not what configuration
they load.

A side benefit of moving off `cache.app`: `lastSyncedAt()`, what decides whether the next
`vigie:threat:sync` run is a delta or a full `--startup` resync, lives in the same Redis item as the
decisions themselves, so it survives a redeploy of the node running the sync (a recreated container,
`var/cache` wiped). Left on a filesystem pool, a routine deploy of that one node can trigger an unwanted
resync.

### Run `vigie:threat:sync` from exactly one place

[doc/threat.md](threat.md) already covers why: CrowdSec's LAPI keeps the delta cursor server-side, keyed by
API key, and two processes sharing a key silently split the delta between them. One node (or one dedicated
cron/worker host, as opposed to the nodes serving HTTP traffic) running the sync with a single API key
sidesteps that entirely: there's no need for a key per node once the store itself is shared, and running it
from several places would only multiply LAPI calls and writes for no benefit.

With a single writer, the fact that `CacheThreatDecisionStore` applies a batch as a plain read-modify-write,
no lock and no compare-and-swap since PSR-6 offers neither, stops being a concern: there's no second writer
to race against. The one residual case, two `vigie:threat:sync` invocations overlapping on that same host
(a slow LAPI response causing the next cron tick to start before the previous one finished), is what the
command's own `symfony/lock` guard exists for. See [doc/threat.md](threat.md).

### If a push source is added later

`threat.ingest` (a SIEM pushing decisions instead of being polled, Wazuh, Sentinel, any SOAR) is a separate,
opt-in feature, off by default; nothing above assumes it's in use. Turning it on while running a fleet
reopens the exact question this page just closed for the pull side: a push lands on whichever node the load
balancer routes it to, and from there the same shared-pool requirement applies, but now with a second
writer (the node that received the push) running concurrently with the sync host, and the plain
read-modify-write above is no longer a theoretical concern. That combination needs its own look before
enabling it in a fleet; it isn't covered here.

### `vigie:threat:list` is fleet-wide truth once the pool is shared

Without a shared pool, this command only ever reports what the node it runs on happens to know, easy to
mistake for the fleet's actual state. Once `threat.cache.pool` is shared, it's the same read path
`ThreatEnforcementSubscriber` uses everywhere, so it reports the truth for the whole fleet from any single
node.
