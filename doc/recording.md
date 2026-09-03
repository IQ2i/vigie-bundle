# Recording activities

## What gets recorded

Security events (login, logout, switch user, token deauthentication) are recorded automatically. HTTP
requests are **opt-in** — see [HTTP requests](#http-requests) below for how to opt one in. Your own
business events go through `custom()` — see [Your own activities](#your-own-activities).

In dev, the Vigie panel of the web profiler says whether the current request was recorded and why (not). Set
`framework.trusted_proxies` if the app sits behind a proxy or load balancer, otherwise every recorded
`ipAddress` is either the proxy's own address or attacker-controlled.

## HTTP requests

Nothing is recorded unless something says so. The decision, in order, first verdict wins:

1. A tagged `ActivityDeciderInterface` — the only mechanism with access to more than the path (query
   string, headers, the security token). Returning `null` abstains.
2. `#[Track]` / `#[Untrack]` on the resolved controller — a method-level attribute wins over a class-level
   one.
3. `http.ignored_paths` — a match here is never recorded, even inside `recorded_paths`.
4. `http.recorded_paths` — a path matching one of these patterns is recorded.
5. The default: **do not record**.

Exclude noisy paths from every environment:

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    http:
        ignored_paths: ['^/_wdt', '^/_profiler', '^/health']
```

```php
use IQ2i\VigieBundle\Attribute as Vigie;

#[Vigie\Track('admin')] // opts every action of this controller into recording
class AdminController
{
    #[Vigie\Track('delete', subject: 'user')] // recorded action: "admin.delete"; subject_id from the route's "id"
    public function delete(int $id): Response {}

    #[Vigie\Untrack] // carved back out — nothing sensitive to log here
    public function autocomplete(): Response {}
}
```

`#[Track]` takes three optional arguments:

- `action` overrides the recorded `action` label. A class-level and a method-level `action` combine,
  joined by a `.`.
- `subject` names the recorded `subject_type`. The method's value wins over the class's.
- `subjectParam` is the route parameter holding the subject id, `id` by default. If the route has no such
  parameter, no subject is recorded.

Applying both `#[Track]` and `#[Untrack]` to the same class or method throws a `LogicException` when the
controller is resolved.

For anything static attributes can't express — a single controller fanning out to different actions through
its query string, like an EasyAdmin dashboard — implement `ActivityDeciderInterface`:

```php
final class EasyAdminDecider implements ActivityDeciderInterface
{
    public function decide(Request $request): ?bool
    {
        if ('admin' !== $request->attributes->get('_route')) {
            return null; // not our concern, let something else decide
        }

        return \in_array($request->query->get('crudAction'), ['new', 'edit', 'delete'], true);
    }
}
```

Multiple deciders can coexist: autoconfigured onto the tag, consulted in priority order (higher runs first),
first non-`null` verdict wins. Filtering on the response status doesn't fit here (the response doesn't exist
yet when a decider runs) — use [`ActivityRecording::cancel()`](#vetoing-a-recording) instead, or widen
`recorded_paths` to cover the surface you want watched.

## Security events

`context` is populated per event type:

- `login_success` — `authenticator`, `interactive`
- `login_failure` — `reason`, `exception`, `authenticator`, `throttled`
- `logout` — nothing
- `switch_user` — `direction` (`'enter'`/`'exit'`), `original_user` (only on `'enter'`)
- `token_deauthenticated` — nothing
- `access_denied` — `attributes` (the denied attributes, e.g. `"ROLE_ADMIN"`, joined by `,` when a voter
  checked several), `subject_type` (`get_debug_type()` of the subject a voter or `#[IsGranted]` was voting
  on, when there was one)
- `csrf_failure` — `token_id` (the id the form or code checked against, e.g. `"authenticate"`,
  `"delete_item"` — never the token value)

`security.record_non_interactive: false` skips a `login_success` from a non-interactive authenticator
(`RememberMeAuthenticator`, a stateless API token) instead of merely flagging it — useful on an API firewall
where every request would otherwise produce a row. `switch_user` covers both directions of impersonation;
filter `context.direction == 'enter'` to count impersonations rather than exits. `context.throttled` means
Symfony refused the attempt without checking the credentials at all (`TooManyLoginAttemptsAuthenticationException`)
— it says nothing about whether the password was actually wrong.

`access_denied` is recorded when an already-authenticated token (`TokenInterface::getUser()` non-null) hits
an `AccessDeniedException` (a voter, `denyAccessUnlessGranted()`, `#[IsGranted]`) or an
`AccessDeniedHttpException` (thrown directly by a controller) — an anonymous visitor is excluded entirely,
since the firewall just sends them to the login page instead, never a signal. This also means a
`RememberMeToken` denial, which Symfony redirects to the firewall's entry point rather than answering with a
403, still produces `access_denied` even though the response isn't one. The `http_request` activity for the
same request, whatever status code the HTTP layer decided on, is still recorded independently — the two
lines are correlated by `http.request.id`, never deduplicated. `security.record_access_denied: false` turns
this off.

`csrf_failure` decorates `security.csrf.token_manager` — every `isTokenValid()` call across the application
is covered, not just the login form (already covered separately as `login_failure` with
`exception: InvalidCsrfTokenException`). That includes a manual check your own code makes before a
sensitive action outside a form; a `false` there is recorded the same way a form's would be.
`security.record_csrf_failure: false` turns this off; it's already a no-op when `symfony/security-csrf`
isn't installed or `framework.csrf_protection` is off.

## Your own activities

```php
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;

final class SomeService
{
    public function __construct(
        private ActivityRecorderInterface $recorder,
    ) {
    }

    public function doSomethingSensitive(): void
    {
        $this->recorder->custom('export.completed', ['rows' => 42]);
    }
}
```

`custom(string $action, array $context = [], ?Subject $subject = null)` fills in `occurredAt` and whatever
the registered [processors](#processors) can find on their own (user, IP, session, request id) from the
current request and security token. For anything a processor can't infer — recording on behalf of a
different user, or from a context with no current request (a CLI command, a queue worker) — build the
`Activity` yourself and call `record()`:

```php
use IQ2i\VigieBundle\Model\Activity;

$this->recorder->record(Activity::custom(
    action: 'export.completed',
    occurredAt: new \DateTimeImmutable(),
    userIdentifier: $userIdentifier,
));
```

`context` is free-form and entirely under your control — it's emitted as `vigie.context` in the ECS
document, see [doc/siem.md](siem.md). Prefer `action` (and `subject`, for the entity an action targeted —
see below), both first-class ECS fields, over a `context` key for anything a SIEM query should match on
directly.

### Subject

`IQ2i\VigieBundle\Model\Subject` is a minimal `type`/`id` pair — `type` a free-form string you choose
(`"user"`, `"order"`), `id` a `string|int` always stored as a string:

```php
use IQ2i\VigieBundle\Model\Subject;

$this->recorder->custom('export.completed', ['rows' => 42], subject: new Subject('export', $export->getId()));
```

Emitted as `vigie.subject.type`/`vigie.subject.id` in the ECS document — see [doc/siem.md](siem.md).

### Security events only the application knows about

A password change, a role change: no Symfony event exists for these, but they're among the strongest
signals of a compromised account. `security(ActivityType $type, ?string $userIdentifier = null, array
$context = [], ?Subject $subject = null)` is the `custom()` shape for the two event types Vigie already
knows the ECS mapping for — `ActivityType::PasswordChanged` and `ActivityType::RolesChanged` — instead of
falling into `custom()`'s empty ECS category:

```php
use IQ2i\VigieBundle\Model\ActivityType;

$this->recorder->security(ActivityType::RolesChanged, context: [
    'added' => 'ROLE_ADMIN',
    'removed' => 'ROLE_GUEST',
]);
```

A null `$userIdentifier` is filled in from the current security token, like every other field the
processors can find; pass one explicitly when it isn't the acting user — an admin changing someone else's
roles, for instance. `security(ActivityType::Custom, ...)` and `security(ActivityType::HttpRequest, ...)`
throw an `\InvalidArgumentException`: those two have their own named constructor, use `custom()` or
`httpRequest()`/`record()` instead.

Suggested `context` keys: `roles_changed` — `added`, `removed` (each joined by `,` for more than one role),
`by` (the admin who made the change, when different from the user); `password_changed` — `reason`
(`'user'`, `'reset'`, `'admin'`). See [doc/recipes.md](recipes.md) for a password-reset listener built on
`security()`, and for scheb/2fa and login-link listeners built on `custom()`.

## Processors

Every activity passing through `ActivityRecorder` — HTTP, security, or your own — runs through processors
tagged `vigie.activity_processor`, on the model of `Monolog\Processor\ProcessorInterface`: a plain callable
run before `record.*` redaction.

```php
interface ActivityProcessorInterface
{
    public function __invoke(Activity $activity): Activity;
}
```

The bundle registers two, both following **fill, never overwrite** — a field or context key the activity
already carries is left untouched:

- `RequestContextProcessor` fills `ipAddress`, `userAgent`, `firewall`, `sessionId`, `requestId`, and
  `context.host`, `context.scheme`, `context.referer`, `context.authenticated`, `context.duration_ms` and,
  on a 4xx/5xx, `context.exception_class` — all from the current request.
- `TokenProcessor` fills `userIdentifier` and `context.impersonator` from the current security token.

Add your own the same way:

```php
final readonly class TenantProcessor implements ActivityProcessorInterface
{
    public function __invoke(Activity $activity): Activity
    {
        return $activity->withAddedContext(['tenant' => $this->currentTenantId()]);
    }
}
```

Autoconfigured onto `ActivityProcessorInterface` — no manual tagging needed. An optional `priority` tag
attribute controls order (higher runs first); a throwing processor never loses the activity, only what it
would have added.

## Vetoing a recording

`IQ2i\VigieBundle\Event\ActivityRecording` is dispatched right before an activity is stored or dispatched,
after redaction, so a listener never sees a value `record.*` asked to drop. `$event->cancel()` discards the
activity entirely; `$event->addContext(...)` enriches it instead, for the cases a processor can't cover
(heavier dependencies, logic conditional on the redacted activity):

```php
#[AsEventListener]
final class TenantContextListener
{
    public function __invoke(ActivityRecording $event): void
    {
        $event->addContext('tenant', $this->currentTenantId());
    }
}
```

A throwing listener never loses the activity either. This runs synchronously, in the request/event context
that originated the activity — there is no queued or deferred recording.

## The `Activity` model

Three named constructors — `httpRequest()`, `security()`, `custom()` — cover the three shapes; see
`src/Model/Activity.php` for the full field list and their types. Each field also has a `with*()` wither
returning a new instance. `eventId` is a durable identifier (a UUIDv7) minted once per activity and
carried unchanged through every wither — see [doc/storage.md](storage.md).

## Request correlation

Every main request carries a correlation id (`Activity::$requestId`, readable from
`$request->attributes->get(RequestIdSubscriber::ATTRIBUTE)`) — a UUIDv7 by default, or a trusted inbound
header via `http.request_id_header`. It links an `http_request` activity back to whatever security activity
(a `login_failure`, for instance) the same request also produced.

## Edge cases

- Recording is fail-safe everywhere: an unwritable log file, a throwing processor or token never turns a
  successful request or login into a 500 — the failure is logged on the `vigie` channel instead.
- Only the main request is captured — a sub-request (an ESI fragment, an embedded controller call) is never
  recorded.
- An empty string for any nullable `string` field on `Activity` normalizes to `null`.
- A `context` entry whose value isn't a scalar or `null` is silently dropped, never thrown over.
- An `http_request` enforced by `threat.enforce` carries the remediation type in `vigie.remediation` — see
  [Enforcing a decision](threat.md#enforcing-a-decision).

See [doc/configuration.md](configuration.md) for every `record.*` field and its pseudonymization modes.
