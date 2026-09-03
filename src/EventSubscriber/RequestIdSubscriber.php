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

use IQ2i\VigieBundle\Uid\UidGenerator;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Stamps every main request with a correlation id, in the "_vigie_request_id"
 * request attribute, so an http_request activity and the login_failure/
 * login_success/switch_user activity it carried can be linked back together
 * (see doc/recording.md — request correlation).
 *
 * Runs at a very high priority (well before SecurityBundle's firewall
 * listener, priority 8) so the id already exists by the time a security
 * event fires during authentication.
 */
final readonly class RequestIdSubscriber implements EventSubscriberInterface
{
    public const ATTRIBUTE = '_vigie_request_id';
    private const TRUSTED_PATTERN = '/^[A-Za-z0-9._-]{1,64}$/';

    public function __construct(
        private ?string $requestIdHeader = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 1024],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $request->attributes->set(self::ATTRIBUTE, self::resolve($request, $this->requestIdHeader));
    }

    private static function resolve(Request $request, ?string $header): string
    {
        if (null !== $header) {
            $trusted = $request->headers->get($header);

            // A client-supplied id is only trusted when it looks like one —
            // otherwise a request could poison correlation with arbitrary
            // (and arbitrarily large) header content.
            if (\is_string($trusted) && 1 === preg_match(self::TRUSTED_PATTERN, $trusted)) {
                return $trusted;
            }
        }

        return UidGenerator::generate();
    }
}
