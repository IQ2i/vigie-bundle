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

use IQ2i\VigieBundle\Event\ThreatDecisionMatched;
use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Threat\ThreatCheckerInterface;
use IQ2i\VigieBundle\Threat\ThreatSubject;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Turns the highest threat decision matching a request into a response,
 * following the threat.enforce.remediations table. The response is set
 * directly on the event rather than thrown as an exception, so a banned
 * request never reaches ErrorListener or a Twig error page.
 *
 * Runs in two stages, both on kernel.request:
 *
 * - The network stage (priority 16, above the firewall's 8, below
 *   RouterListener's 32): ip/country/asn only. It must run before an
 *   authenticator gets a chance to check credentials and set a response of
 *   its own (RequestEvent::setResponse() stops propagation), or a banned IP
 *   could authenticate freely: any authenticator that answers a login
 *   attempt, success or failure, with its own response - which is the
 *   common case - would otherwise keep the identity stage from ever running.
 * - The identity stage (priority 7, under the firewall): session/username
 *   only, once the token exists. Never reached for a request the network
 *   stage already answered, by construction of setResponse().
 *
 * A decision matching the network stage always wins over one matching the
 * identity stage on the same request, even at a lower ThreatRemediation
 * priority: refusing the IP happens before spending a credentials check to
 * find out what the identity stage would have decided.
 *
 * Fail-open: an unreachable store, a listener that throws, or a route that
 * no longer exists lets the request through instead of turning it into a 500.
 */
final class ThreatEnforcementSubscriber implements EventSubscriberInterface
{
    public const ATTRIBUTE = '_vigie_remediation';

    /**
     * @var list<string>
     */
    private readonly array $routes;

    /**
     * @param array<string, int|string> $remediations remediation type mapped to an HTTP status or a route name
     * @param list<string>              $excludePaths path patterns, without delimiters
     */
    public function __construct(
        private readonly ThreatCheckerInterface $checker,
        private readonly array $remediations = [],
        private readonly array $excludePaths = [],
        private readonly ?string $countryHeader = null,
        private readonly ?string $asnHeader = null,
        private readonly ?EventDispatcherInterface $dispatcher = null,
        private readonly ?TokenStorageInterface $tokenStorage = null,
        private readonly ?UrlGeneratorInterface $urlGenerator = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->routes = array_values(array_filter($remediations, \is_string(...)));
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => [
                ['onNetworkStage', 16],
                ['onIdentityStage', 7],
            ],
        ];
    }

    public function onNetworkStage(RequestEvent $event): void
    {
        $this->enforce($event, fn (Request $request): ThreatSubject => ThreatSubject::network(
            $request,
            $this->countryHeader,
            $this->asnHeader,
        ));
    }

    public function onIdentityStage(RequestEvent $event): void
    {
        $this->enforce($event, fn (Request $request): ThreatSubject => ThreatSubject::identity(
            $request,
            $this->tokenStorage?->getToken()?->getUserIdentifier(),
        ));
    }

    /**
     * @param \Closure(Request): ThreatSubject $subjectFactory
     */
    private function enforce(RequestEvent $event, \Closure $subjectFactory): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $route = $request->attributes->get('_route');

        // A route named in the table is a remediation itself (e.g. the captcha page): excluded, or it would redirect to itself.
        if (\is_string($route) && \in_array($route, $this->routes, true)) {
            return;
        }

        $path = $request->getPathInfo();

        foreach ($this->excludePaths as $pattern) {
            if (preg_match('{'.$pattern.'}u', $path)) {
                return;
            }
        }

        try {
            $subject = $subjectFactory($request);

            $decisions = $this->checker->decisionsFor($subject);

            if ([] === $decisions) {
                return;
            }

            $matched = new ThreatDecisionMatched($request, $subject, $decisions[0], $decisions);
            $this->dispatcher?->dispatch($matched);

            $response = $matched->getResponse() ?? $this->fromTable($decisions[0]);

            if (null === $response) {
                return;
            }

            $request->attributes->set(self::ATTRIBUTE, $decisions[0]->type);
            $event->setResponse($response);
        } catch (\Throwable $e) {
            $this->logger?->error('Vigie could not enforce a threat decision: {message}', [
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);
        }
    }

    private function fromTable(ThreatDecision $decision): ?Response
    {
        $action = $this->remediations[$decision->type] ?? null;

        return match (true) {
            \is_int($action) => new Response(status: $action),
            \is_string($action) && null !== $this->urlGenerator => new RedirectResponse($this->urlGenerator->generate($action)),
            default => null,
        };
    }
}
