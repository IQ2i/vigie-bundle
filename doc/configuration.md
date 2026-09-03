# Configuration

Full reference for the `iq2i_vigie` configuration tree. Run `php bin/console config:dump-reference
iq2i_vigie` for the same tree with every option's description inline.

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    # Disable the whole bundle (no subscriber, no service is registered)
    enabled: true

    # Stamped as "service.name"/"service.environment" on every recorded ECS
    # document — lets an external consumer reading several applications' or
    # environments' streams tell them apart. "app" defaults to null (omitted);
    # "env" defaults to the current kernel environment.
    app: null
    env: '%kernel.environment%'

    # Service id implementing ActivityStorageInterface, or "in_memory" to use
    # the bundle's in-memory test double. Defaults to "monolog": activities
    # are logged as ECS (Elastic Common Schema) documents through a dedicated
    # Monolog channel — see "output" below and doc/storage.md.
    storage: null

    # Settings for the built-in Monolog storage (storage: "monolog", the
    # default) — see doc/storage.md.
    output:
        # Stream URL the default handler writes NDJSON to when "handlers" is
        # empty — an absolute path, or e.g. "php://stdout" for a
        # containerized deployment. Ignored once "handlers" is non-empty.
        path: '%kernel.logs_dir%/vigie.jsonl'
        # Service ids implementing Monolog\Handler\HandlerInterface. Empty
        # (the default) makes Vigie create a single StreamHandler on "path"
        # with its own ECS formatter — see doc/storage.md.
        handlers: []

    # Individually toggle which fields get recorded, wherever the activity
    # comes from — a field disabled here is nulled out (or pseudonymized)
    # before the activity ever reaches a storage or an ActivityRecording
    # listener.
    record:
        ip_address: anonymize  # true | false | 'anonymize' (the default)
        user_agent: true
        user_identifier: true  # true | false | 'hash'
        uri: true
        query_string: false    # keep the query string as part of "uri" — see doc/siem.md (url.query)
        route: true
        method: true
        status_code: true
        context: true
        firewall: true
        session_id: true       # always HMACed when true, never stored raw
        request_id: true
        route_params: false    # copy scalar route params into context, never overwriting an existing key
        hash_secret: null      # keys the HMAC behind user_identifier: hash and session_id; defaults to %kernel.secret%

    http:
        # Track HTTP requests
        enabled: true
        # Regular expressions (without delimiters) matched against the request path.
        # A match is never recorded — an exception carved out of recorded_paths.
        ignored_paths: []
        # Regular expressions (without delimiters) matched against the request path.
        # Nothing is recorded by default (opt-in); a path is recorded only once it
        # matches one of these patterns (e.g. ["^/admin"] to record the backoffice)
        # — ignored_paths still applies on top of it. Use #[Track] to opt in a
        # controller instead of a path pattern.
        recorded_paths: []
        # Inbound header trusted as the request correlation id when it looks
        # like one (e.g. "X-Request-Id"). Null never trusts the client.
        request_id_header: null

    security:
        # Track login, logout, switch user and access-denied events
        enabled: true
        # Whether a login_success from a non-interactive authenticator
        # (RememberMeAuthenticator, a stateless API authenticator) is recorded.
        record_non_interactive: true
        # Whether an AccessDeniedException/AccessDeniedHttpException hitting an
        # already-authenticated token is recorded as access_denied. An anonymous
        # visitor redirected to the login page is never a signal and is always
        # excluded, regardless of this option.
        record_access_denied: true
        # Whether a false isTokenValid() on security.csrf.token_manager is
        # recorded as csrf_failure. Requires symfony/security-csrf and
        # framework.csrf_protection to be active; a no-op otherwise,
        # independent of the "enabled" option above.
        record_csrf_failure: true

    # Ingests the decisions a SIEM (CrowdSec today) hands back about suspicious
    # IPs, ranges, sessions, users, countries and AS numbers — see doc/threat.md.
    threat:
        enabled: false
        # Service id implementing ThreatProviderInterface, or "crowdsec" to use
        # the built-in CrowdSec LAPI provider. Required when threat.enabled is true.
        provider: null
        # Service id implementing ThreatDecisionStoreInterface, "cache", or
        # "in_memory". Defaults to "cache".
        storage: null

        cache:
            # Service id of a PSR-6 CacheItemPoolInterface — holds the decisions
            # when threat.storage is "cache" and the accepted ingest signatures
            # when threat.ingest is on.
            pool: 'cache.app'

        match:
            # Push a session id/user identifier through QueryNormalizer before
            # looking it up, so a decision authored from the pseudonymized value
            # a SIEM actually sees still matches. Never applies to the IP.
            normalize_subject: true
            # Cap on how many "Range" decisions one IP lookup loads and tests.
            max_ranges: 5000

        # Opt-in enforcement — see doc/threat.md.
        enforce:
            enabled: false
            # ThreatChecker::highestFor() → an action, indexed by remediation
            # type. A type absent from this table is never acted on, but
            # ThreatDecisionMatched is dispatched regardless.
            remediations: {}    # e.g. { ban: 403, captcha: app_captcha }
            # Regular expressions (without delimiters) matched against the
            # request path; a match is never enforced.
            exclude_paths: []
            # Trusted headers for the country/AS number, passed to
            # ThreatSubject::fromRequest().
            country_header: null
            asn_header: null

        # HTTP endpoint a SIEM pushes decisions to — see doc/threat.md. Nothing
        # is reachable until the application imports
        # "@IQ2iVigieBundle/config/routes.php".
        ingest:
            enabled: false
            # One shared secret per emitting SIEM, keyed by the provider name
            # in the URL. Required when ingest.enabled is true.
            providers: {}    # e.g. { wazuh: '%env(VIGIE_INGEST_WAZUH_SECRET)%' }
            max_body_size: 1048576    # bytes
            clock_skew: 300           # seconds

        # Settings for the built-in CrowdSec provider (threat.provider: "crowdsec").
        # Targets the Local API (LAPI), never the Central API.
        crowdsec:
            url: 'http://127.0.0.1:8080'
            # Bouncer API key, created with "cscli bouncers add <name>" — read-only
            # by design. Required when threat.provider is "crowdsec".
            api_key: null
            # Scopes requested from the LAPI stream, sent verbatim — the LAPI
            # itself defaults to "ip,range" only.
            scopes: ['Ip', 'Range']
            # Restrict the stream to these decision origins. Empty means every origin.
            origins: []
            scenarios_containing: []
            timeout: 5.0
            # Service id of an HttpClientInterface to use instead of the default
            # scoped one Vigie creates from "url"/"timeout" — it must carry the
            # LAPI base URI itself, "url" is then ignored.
            http_client: null
```

## What gets disabled, and when

- `enabled: false` — nothing is registered at all: not a single subscriber, command, or service.
- `http.enabled: false` / `security.enabled: false` — the corresponding subscriber (and, for `http`, the
  request-id and `#[Track]`/`#[Untrack]` subscribers) isn't registered.
- `threat.enabled: false` (the default) — no `ThreatCheckerInterface`, no `ThreatDecisionStoreInterface`,
  no `vigie:threat:*` command — see [doc/threat.md](threat.md).

## Optional dependencies

- `symfony/monolog-bundle` — only needed to declare an `output.handlers` entry through `monolog.yaml`
  instead of `config/services.yaml`; the default `monolog` storage works without it — see
  [doc/storage.md](storage.md).
- `symfony/security-http` — login, logout and switch user tracking. Without it, `SecurityActivitySubscriber`
  isn't registered.
- `symfony/security-csrf` — CSRF failure tracking. Without it, or without `framework.csrf_protection`
  active, the `security.csrf.token_manager` decorator isn't registered.
- `symfony/console` — the `vigie:*` commands. Without it, they simply aren't registered.
- `symfony/uid` — UUIDv7 request correlation ids and event ids. Without it, both fall back to random bytes:
  still unique, just not sortable/timestamped.
- `symfony/web-profiler-bundle` (dev, with `kernel.debug: true`) — the Vigie panel in the debug toolbar.
  Without it, the collector isn't registered and there's no panel.
- `symfony/http-client` — the built-in CrowdSec threat provider (`threat.provider: "crowdsec"`). Setting it
  without the package installed throws a `LogicException` at boot; a custom `ThreatProviderInterface` has
  no such requirement.
- `symfony/routing` — redirecting to a route from `threat.enforce.remediations`, and the threat ingest
  endpoint (`threat.ingest.enabled: true`). A `LogicException` at boot says so when either is on without it.

## Logging

Everything the bundle logs about its own operation (a failed recording, a failed threat sync) goes to the
`vigie` Monolog channel (`monolog.logger` tag) — route it to its own handler to keep it out of the
application's default log:

```yaml
# config/packages/monolog.yaml
monolog:
    channels: ['vigie']
    handlers:
        vigie:
            type: stream
            path: '%kernel.logs_dir%/vigie.log'
            channels: ['vigie']
```

This is separate from `vigie.activity`, the channel the default Monolog storage writes ECS documents to —
see [doc/storage.md](storage.md). Without `symfony/monolog-bundle` installed, the `vigie` channel tag has
no effect and logging goes through the plain `logger` service instead — nothing is lost, it just isn't
separated out.
