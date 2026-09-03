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
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Turns the highest threat decision matching a request into a response,
 * following the threat.enforce.remediations table — an HTTP status code, or
 * a redirect to a named route. Opt-in: without threat.enforce.enabled this
 * service isn't even registered, and Vigie decides nothing by itself. The
 * response is set directly on the event rather than thrown as an exception,
 * so a banned request never reaches ErrorListener or a Twig error page.
 *
 * Fail-open throughout: an unreachable store, a listener that throws, or a
 * route that no longer exists lets the request through instead of turning it
 * into a 500.
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
            // Just under the firewall (8): routing already ran (RouterListener
            // is at 32, so _route is set and a route named in the table can be
            // recognized) and the token exists, so a "username" scope decision
            // can match the authenticated visitor.
            KernelEvents::REQUEST => ['onKernelRequest', 7],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $route = $request->attributes->get('_route');

        // A route named in the table is the way *out* of a remediation (the
        // captcha page): enforcing on it would redirect it to itself.
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
            $subject = ThreatSubject::fromRequest(
                $request,
                $this->tokenStorage?->getToken()?->getUserIdentifier(),
                $this->countryHeader,
                $this->asnHeader,
            );

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

            // Read back by HttpActivitySubscriber into Activity::$remediation,
            // so a scenario can exclude the very lines its own decisions
            // caused.
            $request->attributes->set(self::ATTRIBUTE, $decisions[0]->type);
            $event->setResponse($response);
        } catch (\Throwable $e) {
            $this->logger?->error('Vigie could not enforce a threat decision: {message}', [
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);
        }
    }

    /**
     * No response for a type absent from the table: the event was
     * dispatched, that's all this remediation asked for.
     */
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
