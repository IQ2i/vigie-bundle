# Reading back a SIEM's decisions

A SIEM (CrowdSec today) can analyze the activity stream Vigie records and decide an IP, a range, a session,
a user, a country or an AS number is suspicious. This page covers getting those decisions back into the
application: a read API, an opt-in enforcement listener, and an event — fed either by polling a provider
(`vigie:threat:sync`) or by a SIEM pushing a signed batch to an HTTP endpoint (`threat.ingest`). Enforcement
is opt-in (`threat.enforce.enabled`) and one-directional: Vigie never pushes a decision of its own back out
to a SIEM.

## Quickstart

```bash
composer require symfony/http-client   # only needed for the built-in CrowdSec provider
cscli bouncers add symfony-vigie       # on the CrowdSec host — prints a bouncer API key
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

Turn a decision into a response — see [Enforcing a decision](#enforcing-a-decision) below for the built-in,
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

`ThreatSubject` is who/what the check is about — `ip`, `sessionId`, `userIdentifier`, `country`, `asn`, all
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
channel, and answers "no decision found" — fail-open.

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

`ThreatEnforcementSubscriber` runs on `kernel.request`, priority 7 — just under the firewall (8): routing
has already run (`_route` is available, so a route named in `remediations` is recognized and excluded from
enforcement) and the security token exists (its identifier enters the `ThreatSubject`, matching a `username`
scope decision). Without `symfony/security-http` installed, it still works without a user identifier (IP,
session, country, AS).

For every matching request it dispatches `ThreatDecisionMatched` — carrying the request, the subject, the
highest-priority decision and every decision that matched — even when `remediations` has no entry for the
type: a listener can call `$event->setResponse()` to replace whatever the table would have done, or just
observe. The response is set directly on the `kernel.request` event, never through an exception. When a
response is set, the request is stamped with the remediation type, which `HttpActivitySubscriber` copies
into `vigie.remediation` on the recorded `http_request` — see [doc/schema/activity-2.0.json](schema/activity-2.0.json).
A scenario should exclude these lines, or a ban enforced by Vigie keeps re-triggering the scenario that issued it.

- The firewall runs first, and a 404 short-circuits enforcement entirely — neither the login redirect nor
  the 404 ever reaches this subscriber, and the `http_request` line isn't stamped either.
- `getClientIp()` depends on `framework.trusted_proxies` — get it wrong and every visitor behind the proxy
  shares its address and risks getting banned together.
- A route named in the table is excluded globally, for every decision type — not just the one whose
  remediation points at it.

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
        // A --startup resync replays every currently active decision —
        // skip it, or every scheduled restart looks like a fresh wave of bans.
        if ($event->startup) {
            return;
        }

        foreach ($event->added as $decision) {
            if ('ban' === $decision->type) {
                // notify, revoke a session, disable an account…
            }
        }

        foreach ($event->removed as $decision) {
            // a ban expired or was revoked — undo whatever $added did
        }
    }
}
```

`$decision->value` here is exactly what the SIEM reported — an unmasked IP, a raw CIDR — never
pseudonymized: `record.*` governs what Vigie itself emits (see [doc/configuration.md](configuration.md)), not what a
third party hands back.

See [doc/remediation.md](remediation.md) for what the comment in `$event->added` above actually looks like:
revoking a session, locking an account, disabling it, notifying.

## The pseudonymization pitfall

Vigie's own ECS output is meant to be acquired by CrowdSec (or any other SIEM) directly — see
[doc/siem.md](siem.md) for the acquisition configuration. But the same field governs both what a scenario
can see and what a decision can later match on: Vigie anonymizes IPs by default
(`record.ip_address: anonymize`, `1.2.3.4` → `1.2.3.0`), so a scenario fed that output only ever sees a
`/24`/`/64` and emits decisions that never match a real IP. Set `record.ip_address: true` before pointing an
acquisition at Vigie's output if a scenario needs to see and ban real addresses.

On the read side, `ThreatSubject::fromRequest()` always matches the IP raw, via `Request::getClientIp()` —
`framework.trusted_proxies` must be set correctly in production, or that returns the proxy's address instead
of the visitor's. The session id and the user identifier are pushed through `QueryNormalizer` before lookup
by default (`threat.match.normalize_subject: true`), applying the same transformation `record.*` applies at
write time (see [doc/configuration.md](configuration.md)) — turn it off only if you author decisions with
the plain-text value yourself.

## Scopes

- `Ip` — exact, case-insensitive.
- `Range` (CIDR) — an IP falling inside it.
- `Country` — exact, case-insensitive, uppercased (ISO 3166-1 alpha-2). Vigie ships no GeoIP database;
  supply the value yourself, e.g. from a `Cf-IPCountry` header behind Cloudflare.
- `AS` — same, for an AS number.
- `session` / `username` — not CrowdSec constants, exact and case-sensitive, always normalized to
  the HMAC before lookup.

Any other scope a provider emits is stored byte-for-byte and only found by an exact `value` lookup, never
by IP: only `Ip` and `Range` decisions take part in an IP match, whatever their value looks like. A
decision missing a field or carrying an unreadable duration is skipped, counted and logged rather than
stored, so one malformed entry never fails an entire sync.

## Operating `vigie:threat:sync`

```bash
php bin/console vigie:threat:sync                # incremental — a delta since the last run
php bin/console vigie:threat:sync --startup      # force a full resync
php bin/console vigie:threat:sync --no-purge     # skip pruning locally expired decisions
```

CrowdSec's LAPI keeps the delta cursor **server-side, per API key** — not in Vigie's own store. Two
consequences:

- One bouncer API key per consumer. Two processes sharing a key silently split the delta between them.
  A shared cache pool (Redis, Memcached) backing every host needs one `vigie:threat:sync` process and
  one key; a local pool (`cache.adapter.filesystem`, APCu) needs one key per host, since each host's
  store is its own.
- `--startup` is the only recovery path. A wiped or evicted cache pool, a rotated API key,
  pointing at a different LAPI, or changing `crowdsec.scopes`/`origins`/`scenarios_containing` all mean
  the local store no longer reflects reality. `vigie:threat:sync` detects an empty store automatically and
  resyncs on its own; use `--startup` explicitly to be sure. The same goes for a run that pulled but could
  not write to the store (an unreachable Redis, a full disk): the LAPI has already handed that delta out and won't send it
  again — the failure is logged on the `vigie` channel with that reminder.

A startup run pulls before it clears, so a LAPI that is down leaves the previous decisions in place. With
`threat.storage: cache`, the pool's own lifecycle applies: a pool that is cleared or evicted (a deploy
removing `var/cache`, `cache:pool:clear`, Redis eviction) leaves no decision at all until the next sync.

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
        // Fetch, map to ThreatDecision, return the batch — see
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
polled (a webhook, an active response script) doesn't implement this interface at all — see the next
section.

## Push

The reverse of polling a provider: a SIEM (Wazuh active response, a Sentinel playbook, any SOAR) posts a
signed batch of decisions to Vigie instead of waiting to be pulled. Feeds the same store, applies through
the same `ThreatSynchronizer::applyBatch()` as `sync()` does, and dispatches the same `ThreatDecisionsSynced`
— a remediation listener never has to tell a push and a pull apart.

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
// config/routes/vigie.php — imported explicitly, with the prefix of your choice, like
// @WebProfilerBundle. Nothing is reachable until this import exists.
$routes->import('@IQ2iVigieBundle/config/routes.php')->prefix('/vigie');
```

Full key reference, including `max_body_size`/`clock_skew`: [doc/configuration.md](configuration.md).

`iq2i_vigie.threat.ingest.enabled: true` without importing `config/routes.php` compiles and registers the
controller, but the route itself doesn't exist — the endpoint answers a plain 404 from your own router until
the import is added. Requires `symfony/routing`; a `LogicException` at boot says so otherwise.

The route (`POST /threat/ingest/{provider}` under whatever prefix you gave it) must sit **outside every
firewall** — a `security.firewall` pattern with `security: false`, or a stateless firewall with no
authenticator — because the shared secret's signature is the only authentication there is.

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
provider's set of decisions — the same semantics as `vigie:threat:sync --startup`. `origin`/`scenario` are
optional. `type` defaults to `"ban"` when omitted. A `removed` entry only needs its `id` — matching is by
`ThreatDecision::key()` alone. An entry that can't be read is counted in `skipped`, never fatal, the same
posture `CrowdSecProvider` already has for a pull.

Responses: `202` `{"added": n, "removed": n, "skipped": n}` on success; `400` an unreadable body; `401` a
missing/wrong signature, a timestamp outside `ingest.clock_skew`, or a replayed signature; `404` an unknown
provider; `413` a body over `ingest.max_body_size`. No response ever carries an internal error detail — the
reason for a refusal goes to the `vigie` log channel instead.

### Anti-replay

An accepted signature is remembered in `threat.cache.pool` for `ingest.clock_skew` seconds; the same body
signed again inside that window is refused with a `401`. Point `threat.cache.pool` at something that
actually persists between requests (Redis, `cache.adapter.filesystem`) once ingest is on — `cache.adapter.array`
(the default in a test, or an app with no cache configured) forgets between requests, so only the timestamp
window still limits how long a captured request stays replayable. Two requests carrying the exact same
signature, submitted at the same instant, can both be accepted — `apply()` is idempotent, so nothing breaks,
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
