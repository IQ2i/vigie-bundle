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

namespace IQ2i\VigieBundle\Tests\Threat;

use IQ2i\VigieBundle\Threat\ThreatSubject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

final class ThreatSubjectTest extends TestCase
{
    public function testFromRequestReadsTheClientIp(): void
    {
        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '203.0.113.42');

        $subject = ThreatSubject::fromRequest($request);

        self::assertSame('203.0.113.42', $subject->ip);
    }

    public function testFromRequestLeavesTheSessionIdNullWhenThereIsNoStartedSession(): void
    {
        $subject = ThreatSubject::fromRequest(Request::create('/'));

        self::assertNull($subject->sessionId);
    }

    public function testFromRequestPassesTheUserIdentifierThrough(): void
    {
        $subject = ThreatSubject::fromRequest(Request::create('/'), userIdentifier: 'jane.doe');

        self::assertSame('jane.doe', $subject->userIdentifier);
    }

    public function testFromRequestReadsCountryAndAsnFromTheConfiguredHeaders(): void
    {
        $request = Request::create('/');
        $request->headers->set('Cf-IPCountry', 'FR');
        $request->headers->set('X-Asn', '1234');

        $subject = ThreatSubject::fromRequest($request, countryHeader: 'Cf-IPCountry', asnHeader: 'X-Asn');

        self::assertSame('FR', $subject->country);
        self::assertSame('1234', $subject->asn);
    }

    public function testFromRequestLeavesCountryAndAsnNullWhenNoHeaderIsConfigured(): void
    {
        $subject = ThreatSubject::fromRequest(Request::create('/'));

        self::assertNull($subject->country);
        self::assertNull($subject->asn);
    }

    public function testFromRequestLeavesCountryNullWhenTheConfiguredHeaderIsAbsent(): void
    {
        $subject = ThreatSubject::fromRequest(Request::create('/'), countryHeader: 'Cf-IPCountry');

        self::assertNull($subject->country);
    }
}
