<?php

declare(strict_types=1);

/*
 * This file is part of the Vigie Bundle.
 *
 * (c) Loïc Sapone <loic@sapone.fr>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace IQ2i\VigieBundle\EventSubscriber;

use IQ2i\VigieBundle\Http\RequestContext;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use IQ2i\VigieBundle\Security\FirewallName;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;
use Symfony\Component\Security\Http\Event\TokenDeauthenticatedEvent;

final readonly class SecurityActivitySubscriber implements EventSubscriberInterface
{
    public function __construct(
        private ActivityRecorderInterface $recorder,
        private ClockInterface $clock,
        private ?TokenStorageInterface $tokenStorage = null,
        private bool $recordNonInteractive = true,
        private bool $recordAccessDenied = true,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
            LoginFailureEvent::class => 'onLoginFailure',
            LogoutEvent::class => 'onLogout',
            SwitchUserEvent::class => 'onSwitchUser',
            TokenDeauthenticatedEvent::class => 'onTokenDeauthenticated',
            // Before Security's own Firewall\ExceptionListener (priority
            // 1), which replaces an AccessDeniedException with a redirect
            // to the login page, or turns it into an AccessDeniedHttpException
            // — by then there is nothing left here to read.
            KernelEvents::EXCEPTION => ['onKernelException', 2],
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        // Never let a failure here block a login that otherwise succeeded.
        try {
            $authenticator = $event->getAuthenticator();
            // Same check core Symfony uses to decide whether to dispatch InteractiveLoginEvent — an authenticator
            // that doesn't implement the interface, or does but returns false, is non-interactive.
            $interactive = $authenticator instanceof InteractiveAuthenticatorInterface && $authenticator->isInteractive();

            if (!$this->recordNonInteractive && !$interactive) {
                return;
            }

            $this->recorder->record(Activity::security(
                type: ActivityType::LoginSuccess,
                occurredAt: $this->clock->now(),
                userIdentifier: $event->getUser()->getUserIdentifier(),
                ipAddress: $event->getRequest()->getClientIp(),
                userAgent: $event->getRequest()->headers->get('User-Agent'),
                context: [
                    'authenticator' => self::shortClassName($authenticator),
                    'interactive' => $interactive,
                ],
                firewall: $event->getFirewallName(),
                sessionId: RequestContext::sessionId($event->getRequest()),
                requestId: RequestContext::requestId($event->getRequest()),
            ));
        } catch (\Throwable $e) {
            $this->logSecurityFailure('login_success', $e);
        }
    }

    public function onLoginFailure(LoginFailureEvent $event): void
    {
        try {
            $exception = $event->getException();
            $userIdentifier = $event->getPassport()?->getBadge(UserBadge::class)?->getUserIdentifier()
                ?? ($exception instanceof UserNotFoundException ? $exception->getUserIdentifier() : null);

            $this->recorder->record(Activity::security(
                type: ActivityType::LoginFailure,
                occurredAt: $this->clock->now(),
                userIdentifier: $userIdentifier,
                ipAddress: $event->getRequest()->getClientIp(),
                userAgent: $event->getRequest()->headers->get('User-Agent'),
                context: [
                    'reason' => $exception->getMessageKey(),
                    'exception' => self::shortClassName($exception),
                    'authenticator' => self::shortClassName($event->getAuthenticator()),
                    'throttled' => $exception instanceof TooManyLoginAttemptsAuthenticationException,
                ],
                firewall: $event->getFirewallName(),
                sessionId: RequestContext::sessionId($event->getRequest()),
                requestId: RequestContext::requestId($event->getRequest()),
            ));
        } catch (\Throwable $e) {
            $this->logSecurityFailure('login_failure', $e);
        }
    }

    public function onLogout(LogoutEvent $event): void
    {
        try {
            $this->recorder->record(Activity::security(
                type: ActivityType::Logout,
                occurredAt: $this->clock->now(),
                userIdentifier: $event->getToken()?->getUserIdentifier(),
                ipAddress: $event->getRequest()->getClientIp(),
                userAgent: $event->getRequest()->headers->get('User-Agent'),
                firewall: FirewallName::fromRequest($event->getRequest()),
                sessionId: RequestContext::sessionId($event->getRequest()),
                requestId: RequestContext::requestId($event->getRequest()),
            ));
        } catch (\Throwable $e) {
            $this->logSecurityFailure('logout', $e);
        }
    }

    public function onSwitchUser(SwitchUserEvent $event): void
    {
        try {
            // SwitchUserEvent::getToken() is the *new* token once entering impersonation (a SwitchUserToken
            // wrapping the impersonator's own token), but the *restored* original token once exiting it — only
            // the former identifies an impersonator.
            $token = $event->getToken();
            $entering = $token instanceof SwitchUserToken;
            $originalUser = $entering ? $token->getOriginalToken()->getUserIdentifier() : null;

            $this->recorder->record(Activity::security(
                type: ActivityType::SwitchUser,
                occurredAt: $this->clock->now(),
                userIdentifier: $event->getTargetUser()->getUserIdentifier(),
                ipAddress: $event->getRequest()->getClientIp(),
                userAgent: $event->getRequest()->headers->get('User-Agent'),
                context: [
                    'direction' => $entering ? 'enter' : 'exit',
                    'original_user' => $originalUser,
                ],
                firewall: FirewallName::fromRequest($event->getRequest()),
                sessionId: RequestContext::sessionId($event->getRequest()),
                requestId: RequestContext::requestId($event->getRequest()),
            ));
        } catch (\Throwable $e) {
            $this->logSecurityFailure('switch_user', $e);
        }
    }

    /**
     * Fired by Security's ContextListener when the user reloaded from the
     * session no longer matches the token (password/roles changed, account
     * disabled elsewhere) — a strong signal of a session that was valid a
     * moment ago and suddenly isn't.
     */
    public function onTokenDeauthenticated(TokenDeauthenticatedEvent $event): void
    {
        try {
            $this->recorder->record(Activity::security(
                type: ActivityType::TokenDeauthenticated,
                occurredAt: $this->clock->now(),
                userIdentifier: $event->getOriginalToken()->getUserIdentifier(),
                ipAddress: $event->getRequest()->getClientIp(),
                userAgent: $event->getRequest()->headers->get('User-Agent'),
                firewall: FirewallName::fromRequest($event->getRequest()),
                sessionId: RequestContext::sessionId($event->getRequest()),
                requestId: RequestContext::requestId($event->getRequest()),
            ));
        } catch (\Throwable $e) {
            $this->logSecurityFailure('token_deauthenticated', $e);
        }
    }

    /**
     * A 403 for an anonymous visitor is the firewall sending them to the
     * login page — not a signal. Only an already-authenticated token
     * hitting one is a privilege-escalation attempt worth recording.
     */
    public function onKernelException(ExceptionEvent $event): void
    {
        if (!$this->recordAccessDenied || !$event->isMainRequest()) {
            return;
        }

        try {
            $denied = self::accessDenied($event->getThrowable());

            if (null === $denied) {
                return;
            }

            $user = $this->tokenStorage?->getToken()?->getUser();

            if (null === $user) {
                return;
            }

            $context = [];

            if ($denied instanceof AccessDeniedException) {
                $attributes = self::stringifyAttributes($denied->getAttributes());
                if ([] !== $attributes) {
                    $context['attributes'] = implode(',', $attributes);
                }

                if (null !== $denied->getSubject()) {
                    $context['subject_type'] = get_debug_type($denied->getSubject());
                }
            }

            $request = $event->getRequest();

            $this->recorder->record(Activity::security(
                type: ActivityType::AccessDenied,
                occurredAt: $this->clock->now(),
                ipAddress: $request->getClientIp(),
                userAgent: $request->headers->get('User-Agent'),
                context: $context,
                firewall: FirewallName::fromRequest($request),
                sessionId: RequestContext::sessionId($request),
                requestId: RequestContext::requestId($request),
            ));
        } catch (\Throwable $e) {
            $this->logSecurityFailure('access_denied', $e);
        }
    }

    private static function accessDenied(\Throwable $exception): AccessDeniedException|AccessDeniedHttpException|null
    {
        do {
            if ($exception instanceof AccessDeniedException || $exception instanceof AccessDeniedHttpException) {
                return $exception;
            }
        } while (null !== $exception = $exception->getPrevious());

        return null;
    }

    /**
     * @param array<mixed> $attributes
     *
     * @return list<string>
     */
    private static function stringifyAttributes(array $attributes): array
    {
        return array_values(array_map(
            static fn (mixed $attribute): string => \is_scalar($attribute) || $attribute instanceof \Stringable ? (string) $attribute : get_debug_type($attribute),
            $attributes,
        ));
    }

    private function logSecurityFailure(string $event, \Throwable $e): void
    {
        $this->logger?->error('Vigie could not build the "{event}" activity: {message}', [
            'event' => $event,
            'message' => $e->getMessage(),
            'exception' => $e,
        ]);
    }

    private static function shortClassName(object $object): string
    {
        $name = $object::class;
        $position = strrpos($name, '\\');

        return false !== $position ? substr($name, $position + 1) : $name;
    }
}
