# Reading back a SIEM's decisions

A SIEM (CrowdSec today) can analyze the activity stream Vigie records and decide an IP, a range, a session,
a user, a country or an AS number is suspicious. This page covers getting those decisions back into the
application: a read API, an opt-in enforcement listener, and an event, fed either by polling a provider
(`vigie:threat:sync`) or by a SIEM pushing a signed batch to an HTTP endpoint (`threat.ingest`). Enforcement
is opt-in (`threat.enforce.enabled`) and one-directional: Vigie never pushes a decision of its own back out
to a SIEM.

## Quickstart

```bash
composer require symfony/http-client   # only needed for the built-in CrowdSec provider
cscli bouncers add symfony-vigie       # on the CrowdSec host, prints a bouncer API key
```

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    threat:
        enabled: true
        provider: crowdsec
        crowdsec:
            api_key: '%env(CROWDSEC_API_KEY)%'
```

```
* * * * *      /path/to/bin/console vigie:threat:sync
```

A cron entry syncs at most once a minute; `vigie:threat:sync --watch` under `supervisor` polls every few
seconds instead, see [Operating `vigie:threat:sync`](#operating-vigiethreatsync) below.

Turn a decision into a response, see [Enforcing a decision](#enforcing-a-decision) below for the built-in,
opt-in way, or read a decision back yourself through `ThreatCheckerInterface` (next section) to build your
own logic.

## Reading the store: `ThreatCheckerInterface`

```php
interface ThreatCheckerInterface
{
    /** @return list<ThreatDecision> */
    public function decisionsFor(ThreatSubject $subject): array;

    public function highestFor(ThreatSubject $subject): ?ThreatDecision;
}
```

`ThreatSubject` is who/what the check is about: `ip`, `sessionId`, `userIdentifier`, `country`, `asn`, all
optional. `ThreatSubject::fromRequest()` builds one from the current request:

```php
use IQ2i\VigieBundle\Threat\ThreatSubject;

$subject = ThreatSubject::fromRequest(
    $request,
    userIdentifier: $this->security->getUser()?->getUserIdentifier(),
);
```

`decisionsFor()` returns every active decision matching the subject, ban before captcha (see
`ThreatRemediation::priorityOf()`), longest-remaining-validity first among equal priorities. `highestFor()`
is sugar for the first entry, or `null`. Both are memoized for the lifetime of the request.

A store failure never turns a successful request into a 500: `decisionsFor()` catches, logs on the `vigie`
channel, and answers "no decision found" (fail-open).

## Enforcing a decision

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    threat:
        enforce:
            enabled: true
            remediations: { ban: 403, captcha: app_captcha }
```

Full key reference, including `exclude_paths`/`country_header`/`asn_header`: [doc/configuration.md](configuration.md).

`ThreatEnforcementSubscriber` runs in two stages, both on `kernel.request`:

- The **network stage**, priority 16, *above* the firewall (8): `ip`/`country`/`asn` only. It has to run
  before an authenticator gets a chance to check credentials and set a response of its own — which is the
  common case, on both a failed and a successful login — or a banned IP could authenticate freely:
  `RequestEvent::setResponse()` stops the event's propagation, so once an authenticator has answered, no
  listener further down the chain, including this one, ever runs. Running above the firewall closes that
  gap: an `Ip`/`Range`/`Country`/`AS` decision is enforced before credentials are ever checked. It still runs
  below `RouterListener` (32), so `_route` is available and a route named in `remediations` is recognized.
- The **identity stage**, priority 7, just under the firewall: `session`/`username` only, once the security
  token exists (its identifier enters the `ThreatSubject`, matching a `username` scope decision). It never
  runs for a request the network stage already answered. Without `symfony/security-http` installed, it never
  matches anything and is effectively a no-op.

A decision matching the network stage always wins over one matching the identity stage on the same request,
even at a lower `ThreatRemediation` priority (a `captcha` on the IP outranks a `ban` on the username here):
refusing the IP happens before spending a credentials check to find out what the identity stage would have
decided. A remediation recipe that needs the token or the session (revoking a session, for instance, see
[doc/remediation.md](remediation.md)) can only ever be triggered by the identity stage.

For every matching request, either stage dispatches `ThreatDecisionMatched`, carrying the request, the
subject, the highest-priority decision and every decision that matched, even when `remediations` has no entry
for the type: a listener can call `$event->setResponse()` to replace whatever the table would have done, or
just observe. The response is set directly on the `kernel.request` event, never through an exception. When a
response is set, the request is stamped with the remediation type, which `HttpActivitySubscriber` copies
into `vigie.remediation` on the recorded `http_request`. See [doc/schema/activity.json](schema/activity.json).
A scenario should exclude these lines, or a ban enforced by Vigie keeps re-triggering the scenario that issued it.

- `RouterListener` runs first, and a 404 short-circuits both stages entirely: neither ever reaches this
  subscriber, and the `http_request` line isn't stamped either.
- `getClientIp()` depends on `framework.trusted_proxies`; get it wrong and every visitor behind the proxy
  shares its address and risks getting banned together.
- A route named in the table is excluded globally, for every decision type and both stages, not just the one
  whose remediation points at it.

## Reacting to a sync: `ThreatDecisionsSynced`

`vigie:threat:sync` dispatches this once per run, after the batch is already applied to the store:

```php
use IQ2i\VigieBundle\Event\ThreatDecisionsSynced;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
final class NotifyOnNewBans
{
    public function __invoke(ThreatDecisionsSynced $event): void
    {
        // A --startup resync replays every currently active decision.
        // Skip it, or every scheduled restart looks like a fresh wave of bans.
        if ($event->startup) {
            return;
        }

        foreach ($event->added as $decision) {
            if ('ban' === $decision->type) {
                // notify, revoke a session, disable an account…
            }
        }

        foreach ($event->removed as $decision) {
            // a ban expired or was revoked, undo whatever $added did
        }
    }
}
```

`$decision->value` here is exactly what the SIEM reported, an unmasked IP, a raw CIDR, never
pseudonymized: `record.*` governs what Vigie itself emits (see [doc/configuration.md](configuration.md)), not what a
third party hands back.

See [doc/remediation.md](remediation.md) for what the comment in `$event->added` above actually looks like:
revoking a session, locking an account, disabling it, notifying.

## The pseudonymization pitfall

Vigie's own ECS output is meant to be acquired by CrowdSec (or any other SIEM) directly, see
[doc/siem.md](siem.md) for the acquisition configuration. But the same field governs both what a scenario
can see and what a decision can later match on: Vigie anonymizes IPs by default
(`record.ip_address: anonymize`, `1.2.3.4` → `1.2.3.0`), so a scenario fed that output only ever sees a
`/24`/`/64` and emits decisions that never match a real IP. Set `record.ip_address: true` before pointing an
acquisition at Vigie's output if a scenario needs to see and ban real addresses.

On the read side, `ThreatSubject::fromRequest()` always matches the IP raw, via `Request::getClientIp()`.
`framework.trusted_proxies` must be set correctly in production, or that returns the proxy's address instead
of the visitor's. The session id and the user identifier are pushed through `QueryNormalizer` before lookup
by default (`threat.match.normalize_subject: true`), applying the same transformation `record.*` applies at
write time (see [doc/configuration.md](configuration.md)). Turn it off only if you author decisions with
the plain-text value yourself.

## Scopes

- `Ip`: exact, case-insensitive.
- `Range` (CIDR): an IP falling inside it.
- `Country`: exact, case-insensitive, uppercased (ISO 3166-1 alpha-2). Vigie ships no GeoIP database;
  supply the value yourself, e.g. from a `Cf-IPCountry` header behind Cloudflare.
- `AS`: same, for an AS number.
- `session` / `username`: not CrowdSec constants, exact and case-sensitive, always normalized to
  the HMAC before lookup.

Any other scope a provider emits is stored byte-for-byte and only found by an exact `value` lookup, never
by IP: only `Ip` and `Range` decisions take part in an IP match, whatever their value looks like. A
decision missing a field or carrying an unreadable duration is skipped, counted and logged rather than
stored, so one malformed entry never fails an entire sync.

## Operating `vigie:threat:sync`

```bash
php bin/console vigie:threat:sync                # incremental, a delta since the last run
php bin/console vigie:threat:sync --startup      # force a full resync
php bin/console vigie:threat:sync --no-purge     # skip pruning locally expired decisions
php bin/console vigie:threat:sync --watch                    # keep running, one delta every 2s
php bin/console vigie:threat:sync --watch --interval 10      # every 10s instead
```

`--watch` keeps the process running instead of exiting after one sync: the first iteration behaves
like a plain run (honoring `--startup` if given, or resyncing on its own if the store is empty, see
below), every following one is always a delta. It stays quiet on an iteration that changed nothing,
so a long-running process doesn't fill its log with identical "0 added, 0 removed" lines. `SIGTERM`/
`SIGINT` stop it cleanly, at the next iteration boundary, never mid-sync. There is no LAPI push to
consume here: `--interval` is the only lever on latency, the same `/v1/decisions/stream` endpoint is
polled, just more often than a once-a-minute cron would. A `supervisor` program keeps it running:

```ini
; /etc/supervisor/conf.d/vigie-threat-sync.conf
[program:vigie-threat-sync]
command=/path/to/bin/console vigie:threat:sync --watch
autostart=true
autorestart=true
stopsignal=TERM
```

CrowdSec's LAPI keeps the delta cursor server-side, per API key, not in Vigie's own store. Two
consequences, and `--watch` doesn't change either:

- One bouncer API key per consumer. Two processes sharing a key silently split the delta between them.
  A shared cache pool (Redis, Memcached) backing every host needs one `vigie:threat:sync` process and
  one key; a local pool (`cache.adapter.filesystem`, APCu) needs one key per host, since each host's
  store is its own. A `--watch` process and a cron both running `vigie:threat:sync` are two processes:
  never point them at the same key, run one or the other. The same rule, applied to several different
  applications sharing one CrowdSec instance instead of one fleet: [doc/multi-tenant.md](multi-tenant.md).
- `--startup` is the only recovery path. A wiped or evicted cache pool, a rotated API key,
  pointing at a different LAPI, or changing `crowdsec.scopes`/`origins`/`scenarios_containing` all mean
  the local store no longer reflects reality. `vigie:threat:sync` detects an empty store automatically and
  resyncs on its own; use `--startup` explicitly to be sure. The same goes for a run that pulled but could
  not write to the store (an unreachable Redis, a full disk): the LAPI has already handed that delta out and
  won't send it again. The failure is logged on the `vigie` channel with that reminder.

A startup run pulls before it clears, so a LAPI that is down leaves the previous decisions in place. With
`threat.storage: cache`, the pool's own lifecycle applies: a pool that is cleared or evicted (a deploy
removing `var/cache`, `cache:pool:clear`, Redis eviction) leaves no decision at all until the next sync.

A run already in progress on the same host is skipped, not queued behind it: with `symfony/lock`
installed, `vigie:threat:sync` refuses to start a second time while an earlier run is still going (an
unresponsive LAPI, a slow store) and logs `Another vigie:threat:sync is already running on this host,
skipping this run.` instead. Without `symfony/lock`, this guards nothing: `composer require symfony/lock`
to enable it. Either way, it only ever protects one host. See [doc/multi-server.md](multi-server.md)
for running `vigie:threat:sync` across a fleet. A `--watch` process holds this lock for its whole
session, not once per iteration: a plain cron entry still cannot start alongside it.

## Inspecting the store: `vigie:threat:list`

Answers "why is this IP/session/user blocked?" without needing `cscli` access from the application host,
reading the exact same store `ThreatCheckerInterface` and `ThreatEnforcementSubscriber` do:

```bash
php bin/console vigie:threat:list                                    # everything, up to --limit
php bin/console vigie:threat:list --scope Ip --value 203.0.113.42    # is this address banned?
php bin/console vigie:threat:list --scope username --active-only     # active username-scope decisions only
php bin/console vigie:threat:list --provider crowdsec --format json  # or --format csv
```

- `--scope` is repeatable (`--scope Ip --scope Range`); with exactly one scope given, `--value` is
  normalized the same way a lookup would be (`--scope Country --value fr` looks up `FR`, see
  [Scopes](#scopes)) — with several scopes or none, `--value` is matched byte-for-byte instead.
- `--value` never matches a `Range` decision by an address it covers, only by its own CIDR string; to
  check whether an address falls inside some range, `--scope Ip` still only finds an exact `Ip` decision.
- `--active-only` excludes decisions whose `expiresAt` has already passed (included by default).
- `--limit` (default 50, 1 to 1000) caps how many rows are returned and displayed, not how many are
  scanned to compute the total shown alongside a `table` format.
- `--format table` (the default) prints provider, scope, value, type, origin, scenario and expiry;
  `json` and `csv` additionally carry `external_id` and `synced_at`, meant for scripting rather than
  reading directly.

On a fleet with a shared `threat.cache.pool`, this reports the truth for every node from any single one,
see [doc/multi-server.md](multi-server.md#threat-decisions-in-a-fleet).

## Writing your own decision store

```php
use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;

final class DoctrineThreatDecisionStore implements ThreatDecisionStoreInterface
{
    public function apply(string $provider, array $added, array $removed, \DateTimeImmutable $syncedAt): void { /* ... */ }
    public function clear(string $provider): void { /* ... */ }
    public function lastSyncedAt(string $provider): ?\DateTimeImmutable { /* ... */ }
    public function find(ThreatDecisionQuery $query): array { /* ... */ }
    public function count(ThreatDecisionQuery $query): int { /* ... */ }
    public function purgeExpired(\DateTimeImmutable $now): int { /* ... */ }
}
```

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    threat:
        storage: App\Threat\DoctrineThreatDecisionStore
```

`apply()` must be atomic and idempotent: applying the same batch twice (a retried sync, a replayed push,
see [Push](#push)) must never produce a duplicate, matched by `ThreatDecision::key()`
(`$provider.':'.$externalId`). `clear()` is the "startup" resync path: drop every decision for that
provider and forget its `lastSyncedAt()`, so the next `sync()` treats it as never having run.

`ThreatDecisionQuery` (`scopes`, `value`, `matchIp`, `provider`, `activeAt`, `limit`) is the filter both
`find()` and `count()` receive, built by `ThreatChecker` and by `vigie:threat:list`. `matchIp` is the one
query `CacheThreatDecisionStore`'s plain read-modify-write can't answer efficiently at scale (it loads
every `Ip`/`Range` decision and tests each in PHP, see `IpRange`): a store backed by a real database can
push that containment test down to a query, `Range` decisions stored as an actual CIDR-aware column
instead of a string compared byte-for-byte. `activeAt` is a plain "not expired as of this instant"
filter; `null` includes expired decisions too, as `vigie:threat:list` does by default.

## Writing your own provider

```php
use IQ2i\VigieBundle\Threat\ThreatProviderInterface;
use IQ2i\VigieBundle\Threat\ThreatSyncBatch;

final class MySiemProvider implements ThreatProviderInterface
{
    public function getName(): string
    {
        return 'my-siem';
    }

    public function pull(bool $startup): ThreatSyncBatch
    {
        // Fetch, map to ThreatDecision, return the batch. See
        // CrowdSecProvider for a worked example.
        return new ThreatSyncBatch(added: [...], removed: [...]);
    }
}
```

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    threat:
        provider: App\Threat\MySiemProvider
```

`pull()` is the entire contract: "produce a batch of decisions added or removed, or every active one when
`$startup` is true." The name is stamped on every decision, paired with the provider's own id for it
(`getName()`.`$externalId`), read back as `ThreatDecision::key()`. A SIEM that pushes instead of being
polled (a webhook, an active response script) doesn't implement this interface at all. See the next
section.

## Push

The reverse of polling a provider: a SIEM (Wazuh active response, a Sentinel playbook, any SOAR) posts a
signed batch of decisions to Vigie instead of waiting to be pulled. Feeds the same store, applies through
the same `ThreatSynchronizer::applyBatch()` as `sync()` does, and dispatches the same `ThreatDecisionsSynced`.
A remediation listener never has to tell a push and a pull apart.

### Enabling it

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    threat:
        ingest:
            enabled: true
            providers: { wazuh: '%env(VIGIE_INGEST_WAZUH_SECRET)%' }
```

```php
// config/routes/vigie.php: imported explicitly, with the prefix of your choice, like
// @WebProfilerBundle. Nothing is reachable until this import exists.
$routes->import('@IQ2iVigieBundle/config/routes.php')->prefix('/vigie');
```

Full key reference, including `max_body_size`/`clock_skew`: [doc/configuration.md](configuration.md).

`iq2i_vigie.threat.ingest.enabled: true` without importing `config/routes.php` compiles and registers the
controller, but the route itself doesn't exist. The endpoint answers a plain 404 from your own router until
the import is added. Requires `symfony/routing`; a `LogicException` at boot says so otherwise.

The route (`POST /threat/ingest/{provider}` under whatever prefix you gave it) must sit outside every
firewall, a `security.firewall` pattern with `security: false`, or a stateless firewall with no
authenticator, because the shared secret's signature is the only authentication there is.

### Contract

Headers: `X-Vigie-Timestamp` (Unix time, seconds) and `X-Vigie-Signature: sha256=<hex>`, computed as
`HMAC-SHA256(secret, "<timestamp>.<body>")`.

```json
{
  "startup": false,
  "added": [
    {"id": "wz-4821", "scope": "Ip", "value": "203.0.113.42", "type": "ban",
     "expires_at": "2026-09-02T13:00:00+00:00", "origin": "wazuh", "scenario": "sshd-bruteforce"}
  ],
  "removed": [{"id": "wz-4790"}]
}
```

`expires_at` is RFC 3339, or `null` for a decision that never expires. `startup: true` replaces the whole
provider's set of decisions, the same semantics as `vigie:threat:sync --startup`. `origin`/`scenario` are
optional. `type` defaults to `"ban"` when omitted. A `removed` entry only needs its `id`, matching is by
`ThreatDecision::key()` alone. An entry that can't be read is counted in `skipped`, never fatal, the same
posture `CrowdSecProvider` already has for a pull.

Responses: `202` `{"added": n, "removed": n, "skipped": n}` on success; `400` an unreadable body; `401` a
missing/wrong signature, a timestamp outside `ingest.clock_skew`, or a replayed signature; `404` an unknown
provider; `413` a body over `ingest.max_body_size`. No response ever carries an internal error detail. The
reason for a refusal goes to the `vigie` log channel instead.

### Anti-replay

An accepted signature is remembered in `threat.cache.pool` for `ingest.clock_skew` seconds; the same body
signed again inside that window is refused with a `401`. Point `threat.cache.pool` at something that
actually persists between requests (Redis, `cache.adapter.filesystem`) once ingest is on. `cache.adapter.array`
(the default in a test, or an app with no cache configured) forgets between requests, so only the timestamp
window still limits how long a captured request stays replayable. Two requests carrying the exact same
signature, submitted at the same instant, can both be accepted: `apply()` is idempotent, so nothing breaks,
but it isn't a hard guarantee against every possible race.

### Writing an emitter

The signature, in PHP:

```php
use IQ2i\VigieBundle\Threat\Ingest\RequestSigner;

$timestamp = (string) time();
$signature = RequestSigner::sign($secret, $timestamp, $body);
// X-Vigie-Timestamp: $timestamp
// X-Vigie-Signature: $signature
```

A Wazuh active response script:

```bash
#!/bin/sh
SECRET="$VIGIE_INGEST_WAZUH_SECRET"
TIMESTAMP=$(date +%s)
BODY='{"added":[{"id":"'"$1"'","scope":"Ip","value":"'"$2"'","type":"ban","expires_at":null,"origin":"wazuh"}]}'
SIGNATURE="sha256=$(printf '%s.%s' "$TIMESTAMP" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')"

curl -sS -X POST "https://app.example.com/vigie/threat/ingest/wazuh" \
    -H "Content-Type: application/json" \
    -H "X-Vigie-Timestamp: $TIMESTAMP" \
    -H "X-Vigie-Signature: $SIGNATURE" \
    -d "$BODY"
```

A Sentinel playbook (Logic App): a "Compose" action builds the timestamp and body, then an inline code step
(or an Azure Function) computes the HMAC. Sentinel has no built-in HMAC action, so an HTTP action only posts
it once the signature is computed upstream.

A generic `curl` for any SOAR that can shell out and compute a SHA-256 HMAC:

```bash
TIMESTAMP=$(date +%s)
BODY='{"added":[{"id":"soar-1","scope":"Ip","value":"203.0.113.42","type":"ban"}]}'
SIGNATURE="sha256=$(printf '%s.%s' "$TIMESTAMP" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')"

curl -X POST "https://app.example.com/vigie/threat/ingest/my-soar" \
    -H "X-Vigie-Timestamp: $TIMESTAMP" -H "X-Vigie-Signature: $SIGNATURE" -d "$BODY"
```
