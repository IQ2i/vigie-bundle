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
 * Who/what a ThreatCheckerInterface lookup is about — always built from real,
 * un-pseudonymized values: $ip is the client's actual address, $sessionId the
 * raw cookie value — never the anonymized/HMACed form `record.*` stores.
 * Matching a SIEM's decisions requires what the SIEM actually saw.
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
     * client's country/AS number (e.g. "Cf-IPCountry" behind Cloudflare) —
     * Vigie ships no GeoIP database of its own, see doc/threat.md.
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
}
