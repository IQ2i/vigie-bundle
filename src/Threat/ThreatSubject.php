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

namespace IQ2i\VigieBundle\Threat;

use IQ2i\VigieBundle\Http\RequestContext;
use Symfony\Component\HttpFoundation\Request;

/**
 * Who/what a ThreatCheckerInterface lookup is about. Always built from real,
 * un-pseudonymized values: $ip is the client's actual address, $sessionId
 * the raw cookie value, never the anonymized/HMACed form `record.*` stores.
 */
final readonly class ThreatSubject
{
    public function __construct(
        public ?string $ip = null,
        public ?string $sessionId = null,
        public ?string $userIdentifier = null,
        public ?string $country = null,
        public ?string $asn = null,
    ) {
    }

    /**
     * $countryHeader/$asnHeader name an inbound header trusted to carry the
     * client's country/AS number (e.g. "Cf-IPCountry" behind Cloudflare).
     * Vigie ships no GeoIP database of its own.
     */
    public static function fromRequest(
        Request $request,
        ?string $userIdentifier = null,
        ?string $countryHeader = null,
        ?string $asnHeader = null,
    ): self {
        return new self(
            ip: $request->getClientIp(),
            sessionId: RequestContext::sessionId($request),
            userIdentifier: $userIdentifier,
            country: null !== $countryHeader ? $request->headers->get($countryHeader) : null,
            asn: null !== $asnHeader ? $request->headers->get($asnHeader) : null,
        );
    }

    /**
     * The network-scope half of fromRequest(): ip, country, asn. No
     * sessionId/userIdentifier, since neither is settled yet at the priority
     * ThreatEnforcementSubscriber's network stage runs at (above the
     * firewall: no token, and the session isn't started).
     */
    public static function network(
        Request $request,
        ?string $countryHeader = null,
        ?string $asnHeader = null,
    ): self {
        return new self(
            ip: $request->getClientIp(),
            country: null !== $countryHeader ? $request->headers->get($countryHeader) : null,
            asn: null !== $asnHeader ? $request->headers->get($asnHeader) : null,
        );
    }

    /**
     * The identity-scope half of fromRequest(): sessionId, userIdentifier.
     * No ip/country/asn: ThreatEnforcementSubscriber's network stage already
     * checked those higher up, above the firewall.
     */
    public static function identity(
        Request $request,
        ?string $userIdentifier = null,
    ): self {
        return new self(
            sessionId: RequestContext::sessionId($request),
            userIdentifier: $userIdentifier,
        );
    }
}
