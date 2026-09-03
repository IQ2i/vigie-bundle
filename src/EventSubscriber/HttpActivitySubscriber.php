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
use IQ2i\VigieBundle\Http\TrackingDecider;
use IQ2i\VigieBundle\Http\TrackingDecision;
use IQ2i\VigieBundle\Http\TrackingSource;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\Subject;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use IQ2i\VigieBundle\Security\FirewallName;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Captures the activity on `kernel.response` (the response, and its final
 * status code, must already exist) but only writes it on `kernel.terminate`
 * — under php-fpm the response has already been sent to the client by then,
 * so a slow insert no longer adds latency to the request it's tracking.
 */
final class HttpActivitySubscriber implements EventSubscriberInterface, ResetInterface
{
    private ?Activity $pending = null;

    public function __construct(
        private readonly ActivityRecorderInterface $recorder,
        private readonly ClockInterface $clock,
        private readonly ?TokenStorageInterface $tokenStorage = null,
        private readonly bool $queryString = false,
        private readonly bool $routeParams = false,
        private readonly TrackingDecider $decider = new TrackingDecider(),
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            // Higher than ProfilerListener::onKernelResponse across the whole
            // supported Symfony range, so it runs first: the
            // TrackingDecision::ATTRIBUTE request attribute this sets must
            // exist before the profiler collects, or
            // VigieDataCollector falls back to a "not recorded" default.
            KernelEvents::RESPONSE => ['onKernelResponse', 100],
            KernelEvents::TERMINATE => ['onKernelTerminate', -1000],
        ];
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        // Cleared unconditionally, before any early return below: in a worker runtime (FrankenPHP, RoadRunner) this
        // instance survives across requests, so a stale $pending from an earlier request must never leak into this one's kernel.terminate.
        $this->pending = null;

        if (!$event->isMainRequest()) {
            $event->getRequest()->attributes->set(TrackingDecision::ATTRIBUTE, new TrackingDecision(false, TrackingSource::NotMainRequest));

            return;
        }

        $request = $event->getRequest();
        $route = $request->attributes->get('_route');
        $route = \is_string($route) ? $route : null;

        $decision = $this->decider->decide($request);
        $request->attributes->set(TrackingDecision::ATTRIBUTE, $decision);

        if (!$decision->recorded) {
            return;
        }

        // Never let a failure while building the activity (e.g. a custom
        // token throwing from getUserIdentifier()) turn a successful
        // response into a 500.
        try {
            $token = $this->tokenStorage?->getToken();
            $userIdentifier = $token?->getUserIdentifier();

            $path = $request->getPathInfo();
            $context = [];

            if ($token instanceof SwitchUserToken) {
                $context['impersonator'] = $token->getOriginalToken()->getUserIdentifier();
            }

            if ($this->routeParams) {
                /** @var array<string, mixed> $routeParams */
                $routeParams = $request->attributes->get('_route_params', []);

                foreach ($routeParams as $name => $value) {
                    if (\is_scalar($value) && !\array_key_exists($name, $context)) {
                        $context[$name] = $value;
                    }
                }
            }

            $this->pending = Activity::httpRequest(
                occurredAt: $this->clock->now(),
                method: $request->getMethod(),
                uri: $this->queryString ? $request->getRequestUri() : $request->getBaseUrl().$path,
                statusCode: $event->getResponse()->getStatusCode(),
                route: $route,
                userIdentifier: $userIdentifier,
                ipAddress: $request->getClientIp(),
                userAgent: $request->headers->get('User-Agent'),
                context: $context,
                firewall: FirewallName::fromRequest($request),
                sessionId: RequestContext::sessionId($request),
                requestId: RequestContext::requestId($request),
            );

            $action = $request->attributes->get(TrackingAttributeSubscriber::ACTION_ATTRIBUTE);

            if (\is_string($action)) {
                $this->pending = $this->pending->withAction($action);
            }

            $subject = $request->attributes->get(TrackingAttributeSubscriber::SUBJECT_ATTRIBUTE);

            if ($subject instanceof Subject) {
                $this->pending = $this->pending->withSubject($subject);
            }

            $remediation = $request->attributes->get(ThreatEnforcementSubscriber::ATTRIBUTE);

            if (\is_string($remediation)) {
                $this->pending = $this->pending->withRemediation($remediation);
            }
        } catch (\Throwable $e) {
            $this->logger?->error('Vigie could not build the HTTP request activity: {message}', [
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);
        }
    }

    public function onKernelTerminate(TerminateEvent $event): void
    {
        if (null === $this->pending) {
            return;
        }

        $activity = $this->pending;
        $this->pending = null;

        // Runs after the response was sent, so an uncaught exception here has nothing useful left to affect.
        try {
            $this->recorder->record($activity);
        } catch (\Throwable $e) {
            $this->logger?->error('Vigie could not record the HTTP request activity: {message}', [
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);
        }
    }

    /**
     * Safety net for a worker runtime, called by Symfony between requests for every ResetInterface service.
     */
    public function reset(): void
    {
        $this->pending = null;
    }
}
