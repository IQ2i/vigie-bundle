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

namespace IQ2i\VigieBundle\Processor;

use IQ2i\VigieBundle\Http\RequestContext;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Security\FirewallName;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Fills ipAddress/userAgent/firewall/sessionId/requestId and several context
 * keys from the current main request. Never overwrites a field or context
 * key the activity already carries.
 *
 * Keeps its own reference, captured on kernel.request — by the time an
 * http_request activity is recorded, HttpKernel::handle() has already popped
 * it off RequestStack in its own finally block.
 */
final class RequestContextProcessor implements ActivityProcessorInterface, EventSubscriberInterface, ResetInterface
{
    private ?Request $request = null;
    private ?string $exceptionClass = null;

    public function __construct(
        private readonly ClockInterface $clock = new Clock(),
        private readonly ?TokenStorageInterface $tokenStorage = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => 'onKernelRequest',
            KernelEvents::EXCEPTION => 'onKernelException',
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $this->request = $event->getRequest();
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $this->exceptionClass = $event->getThrowable()::class;
    }

    public function __invoke(Activity $activity): Activity
    {
        $request = $this->request;

        if (null === $request) {
            return $activity;
        }

        if (null === $activity->ipAddress) {
            $activity = $activity->withIpAddress($request->getClientIp());
        }

        if (null === $activity->userAgent) {
            $activity = $activity->withUserAgent($request->headers->get('User-Agent'));
        }

        if (null === $activity->firewall) {
            $activity = $activity->withFirewall(FirewallName::fromRequest($request));
        }

        if (null === $activity->sessionId) {
            $activity = $activity->withSessionId(RequestContext::sessionId($request));
        }

        if (null === $activity->requestId) {
            $activity = $activity->withRequestId(RequestContext::requestId($request));
        }

        $context = [];

        if (!\array_key_exists('host', $activity->context)) {
            $context['host'] = $request->getHost();
        }

        if (!\array_key_exists('scheme', $activity->context)) {
            $context['scheme'] = $request->getScheme();
        }

        if (!\array_key_exists('referer', $activity->context)) {
            $referer = $request->headers->get('Referer');

            if (null !== $referer) {
                $context['referer'] = $referer;
            }
        }

        if (!\array_key_exists('authenticated', $activity->context)) {
            $context['authenticated'] = $this->isAuthenticated();
        }

        if (!\array_key_exists('duration_ms', $activity->context)) {
            $durationMs = $this->durationMs($request);

            if (null !== $durationMs) {
                $context['duration_ms'] = $durationMs;
            }
        }

        if (!\array_key_exists('exception_class', $activity->context) && null !== $this->exceptionClass) {
            $context['exception_class'] = $this->exceptionClass;
        }

        return [] !== $context ? $activity->withAddedContext($context) : $activity;
    }

    /**
     * Safety net for a worker runtime, called between requests — mirrors HttpActivitySubscriber::reset().
     */
    public function reset(): void
    {
        $this->request = null;
        $this->exceptionClass = null;
    }

    private function isAuthenticated(): bool
    {
        $token = $this->tokenStorage?->getToken();

        return null !== $token && null !== $token->getUser();
    }

    /**
     * REQUEST_TIME_FLOAT is set by the SAPI (php-fpm, the built-in server) when it started handling the
     * request — the closest thing to "when this request began" a processor running well after
     * kernel.request can still get to.
     */
    private function durationMs(Request $request): ?int
    {
        $requestTime = $request->server->get('REQUEST_TIME_FLOAT');

        if (!\is_float($requestTime) && !\is_int($requestTime)) {
            return null;
        }

        $now = (float) $this->clock->now()->format('U.u');

        return (int) round(($now - (float) $requestTime) * 1000);
    }
}
