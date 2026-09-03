# Recipes

Vigie ships no code for third-party packages — a scenario an application actually runs on, wired through
`ActivityRecorderInterface::custom()`/`security()`, ten lines each. Adapt the listener class and priority to
how the package in question dispatches its own events.

## scheb/2fa

```php
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvent;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvents;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

final readonly class TwoFactorActivityListener
{
    public function __construct(
        private ActivityRecorderInterface $recorder,
    ) {
    }

    #[AsEventListener(TwoFactorAuthenticationEvents::SUCCESS)]
    public function onSuccess(TwoFactorAuthenticationEvent $event): void
    {
        $this->recorder->custom('two_factor.success');
    }

    #[AsEventListener(TwoFactorAuthenticationEvents::FAILURE)]
    public function onFailure(TwoFactorAuthenticationEvent $event): void
    {
        $this->recorder->custom('two_factor.failure', ['provider' => $event->getTwoFactorToken()->getCurrentTwoFactorProvider()]);
    }
}
```

Symfony's own `login_success` is emitted before the 2FA challenge is even shown — a compromised account
that has the password but not the second factor shows up as a `login_success` immediately followed by
repeated `two_factor.failure` for the same user, and that pairing, not either activity alone, is what a
scenario should match on.

## symfony/login-link

Consuming a login link is already a `login_success` with `context.authenticator: 'LoginLinkAuthenticator'` —
nothing to add. Emitting one isn't recorded anywhere on its own:

```php
use IQ2i\VigieBundle\Model\Subject;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;

final readonly class LoginLinkSender
{
    public function __construct(
        private LoginLinkHandlerInterface $loginLinkHandler,
        private ActivityRecorderInterface $recorder,
    ) {
    }

    public function send(UserInterface $user): void
    {
        $link = $this->loginLinkHandler->createLoginLink($user);

        $this->recorder->custom('login_link.sent', [], new Subject('user', $user->getUserIdentifier()));

        // ... actually send $link->getUrl() by mail
    }
}
```

A spike of `login_link.sent` for the same `vigie.subject.id` is the signal here — a single valid link
requested repeatedly is exactly what an attacker with access to the mailbox but not the account looks like.

## symfonycasts/reset-password

```php
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;

final readonly class ResetPasswordActivityRecorder
{
    public function __construct(
        private ActivityRecorderInterface $recorder,
    ) {
    }

    public function onRequested(): void
    {
        $this->recorder->custom('password_reset.requested');
    }

    public function onCompleted(): void
    {
        $this->recorder->security(ActivityType::PasswordChanged, context: ['reason' => 'reset']);
    }
}
```

Call `onRequested()` where the application handles the reset-request form, and `onCompleted()` once
`ResetPasswordHandlerInterface::removeResetRequest()` has run and the new password is persisted — see
[doc/recording.md](recording.md#security-events-only-the-application-knows-about) for the
`context.reason` values `security()` expects for `password_changed`.
