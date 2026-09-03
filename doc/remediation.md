# Remediation recipes

Vigie ships no code for acting on a threat decision — the same posture [doc/recipes.md](recipes.md) has for
third-party packages. This page shows what that code looks like: a handful of listeners, ten lines each,
hooked onto the two events the `threat` subsystem dispatches.

- `ThreatDecisionsSynced` — once per sync, pull or push (see [doc/threat.md](threat.md)). The right
  place to act on an account: disable it, deauthenticate it, notify about it.
- `ThreatDecisionMatched` — once per request that matches an active decision, dispatched by
  `ThreatEnforcementSubscriber` (`threat.enforce.enabled: true` — see
  [doc/threat.md](threat.md#enforcing-a-decision)). The right place to act on a session: it's the only one
  of the two that carries the current `Request`.

A ban `Ip`/`Range` has no recipe here — enforcement (`threat.enforce.remediations`) is the better fit,
usually paired with the reverse proxy or a CrowdSec bouncer in front of the application. These recipes cover
what a proxy can't see: a `session` or a `username` scope.

## Revoking a session (scope `session`)

A `session`-scoped decision's value is the HMAC of the session id (`ThreatChecker` always normalizes it that
way — see [The pseudonymization pitfall](threat.md#the-pseudonymization-pitfall)) — the raw id behind that
hash is unrecoverable, so there is no `SessionHandlerInterface::destroy()` to call at sync time. The
revocation happens on the session's *next* request instead, through `ThreatDecisionMatched`:

```php
use IQ2i\VigieBundle\Event\ThreatDecisionMatched;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;

#[AsEventListener]
final class RevokeBannedSession
{
    public function __invoke(ThreatDecisionMatched $event): void
    {
        if ('session' !== $event->decision->scope->value || 'ban' !== $event->decision->type) {
            return;
        }

        $event->request->getSession()->invalidate();
        $event->setResponse(new RedirectResponse('/login'));
    }
}
```

Requires `threat.enforce.enabled: true`. The resulting
`http_request` carries `vigie.remediation: ban` — see
[doc/threat.md](threat.md#enforcing-a-decision). Symfony's session is invalidated, but a remember-me cookie
isn't — see the next recipe for that.

## Refusing a connection and disconnecting everywhere (scope `username`)

Two halves, since Symfony has no single hook covering both a login attempt and an already-open session.

### Refusing the login

A `UserCheckerInterface::checkPreAuth()` that asks `ThreatCheckerInterface` and throws `LockedException` on
a `ban`:

```php
use IQ2i\VigieBundle\Threat\ThreatCheckerInterface;
use IQ2i\VigieBundle\Threat\ThreatSubject;
use Symfony\Component\Security\Core\Exception\LockedException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final readonly class ThreatAwareUserChecker implements UserCheckerInterface
{
    public function __construct(
        private ThreatCheckerInterface $checker,
    ) {
    }

    public function checkPreAuth(UserInterface $user): void
    {
        $decision = $this->checker->highestFor(new ThreatSubject(userIdentifier: $user->getUserIdentifier()));

        if (null !== $decision && 'username' === $decision->scope->value && 'ban' === $decision->type) {
            throw new LockedException('Account is locked.');
        }
    }

    public function checkPostAuth(UserInterface $user): void
    {
    }
}
```

The resulting `login_failure` is recorded normally, with `context.reason: 'Account is locked.'` — the SIEM
sees its own decision take effect without an `http_request` line to exclude, since this path never reaches
one. Pass the plain identifier here regardless of how the decision was authored — see
[The pseudonymization pitfall](threat.md#the-pseudonymization-pitfall).

### Disconnecting sessions already open

Symfony doesn't index sessions by user, so there's nothing to
revoke directly. The robust way is a version counter on the user, bumped once per ban, compared on the next
request — either `EquatableInterface::isEqualTo()` or `UserCheckerInterface::checkPostAuth()` throwing when
the stored version is behind. `ContextListener` then deauthenticates the token on its own, producing a
`token_deauthenticated` — already recorded, nothing more to wire for it. The listener here only has to bump
the counter, once per sync, not once per request:

```php
use IQ2i\VigieBundle\Event\ThreatDecisionsSynced;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
final class BumpSessionVersionOnBan
{
    public function __construct(
        private UserRepository $users, // however your app looks a user up
    ) {
    }

    public function __invoke(ThreatDecisionsSynced $event): void
    {
        foreach ($event->added as $decision) {
            if ('username' !== $decision->scope->value || 'ban' !== $decision->type) {
                continue;
            }

            $this->users->findByIdentifierOrHash($decision->value)?->incrementSessionVersion();
        }
    }
}
```

### Finding the user from the decision

With `threat.match.normalize_subject: true` (the default), `$decision->value` is the HMAC
`Pseudonymizer::hash()` would produce for the identifier, not the identifier itself — recommended: a column
on the user, indexed, holding that same hash (computed with `Pseudonymizer::hash()` whenever the identifier
is set), looked up directly rather than iterating every user to compare hashes.

## Disabling an account

A variant of the previous recipe's listener, reacting to the same event:

```php
public function __invoke(ThreatDecisionsSynced $event): void
{
    // A --startup resync (or a pushed "startup": true) replays every
    // currently active decision — acting on it here would re-disable every
    // banned account on every restart.
    if ($event->startup) {
        return;
    }

    foreach ($event->added as $decision) {
        if ('username' === $decision->scope->value && 'ban' === $decision->type) {
            $this->users->findByIdentifierOrHash($decision->value)?->setDisabled(true);
        }
    }

    foreach ($event->removed as $decision) {
        if ('username' === $decision->scope->value) {
            // Notify — an expired or revoked decision is not proof of
            // innocence, so don't re-enable the account automatically.
        }
    }
}
```

## Notifying

One `symfony/notifier` message per sync, not per decision — a CrowdSec sync can carry hundreds of IPs:

```php
use IQ2i\VigieBundle\Event\ThreatDecisionsSynced;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Notifier\ChatterInterface;
use Symfony\Component\Notifier\Message\ChatMessage;

#[AsEventListener]
final readonly class NotifyOnNewBans
{
    public function __construct(
        private ChatterInterface $chatter,
    ) {
    }

    public function __invoke(ThreatDecisionsSynced $event): void
    {
        if ($event->startup || [] === $event->added) {
            return;
        }

        $byScenario = [];
        foreach ($event->added as $decision) {
            if ('ban' === $decision->type) {
                $byScenario[$decision->scenario ?? 'unknown'][] = $decision->value;
            }
        }

        foreach ($byScenario as $scenario => $values) {
            $this->chatter->send(new ChatMessage(\sprintf('%s: %d new ban(s) — %s', $scenario, \count($values), implode(', ', $values))));
        }
    }
}
```

Restrict this to decisions the application itself produced — not a community blocklist pulled in
alongside it — with `threat.crowdsec.origins`/`scenarios_containing` (see
[doc/configuration.md](configuration.md)), filtered again here on `$decision->origin`/`$decision->scenario`
if the provider mixes sources in one stream.
