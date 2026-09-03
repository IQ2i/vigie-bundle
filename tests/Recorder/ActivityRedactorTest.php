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

namespace IQ2i\VigieBundle\Tests\Recorder;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\ActivityRedactor;
use IQ2i\VigieBundle\Recorder\Pseudonymizer;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use PHPUnit\Framework\TestCase;

final class ActivityRedactorTest extends TestCase
{
    private function activity(): Activity
    {
        return Activity::httpRequest(
            occurredAt: new \DateTimeImmutable('2026-08-21 10:00:00'),
            method: 'GET',
            uri: '/dashboard',
            route: 'app_dashboard',
            statusCode: 200,
            userIdentifier: 'jane.doe',
            ipAddress: '203.0.113.1',
            userAgent: 'Symfony',
            context: ['key' => 'value'],
            firewall: 'main',
            sessionId: 'raw-session-id',
            requestId: 'req-1',
        );
    }

    private function redactor(RecordingOptions $options, string $secret = 'test-secret'): ActivityRedactor
    {
        return new ActivityRedactor($options, new Pseudonymizer($secret));
    }

    public function testAllEnabledKeepsEveryFieldExceptSessionIdWhichIsAlwaysHashed(): void
    {
        $result = $this->redactor(new RecordingOptions(ipAddress: true))->redact($this->activity());

        self::assertSame('jane.doe', $result->userIdentifier);
        self::assertSame('203.0.113.1', $result->ipAddress);
        self::assertSame('Symfony', $result->userAgent);
        self::assertSame('/dashboard', $result->uri);
        self::assertSame('app_dashboard', $result->route);
        self::assertSame('GET', $result->method);
        self::assertSame(200, $result->statusCode);
        self::assertSame(['key' => 'value'], $result->context);
        self::assertSame('main', $result->firewall);
        self::assertSame('req-1', $result->requestId);
        self::assertNotSame('raw-session-id', $result->sessionId);
        self::assertSame(64, \strlen((string) $result->sessionId));
    }

    public function testEachToggleNullsOnlyItsOwnField(): void
    {
        self::assertNull($this->redactor(new RecordingOptions(ipAddress: false))->redact($this->activity())->ipAddress);
        self::assertNull($this->redactor(new RecordingOptions(userAgent: false))->redact($this->activity())->userAgent);
        self::assertNull($this->redactor(new RecordingOptions(userIdentifier: false))->redact($this->activity())->userIdentifier);
        self::assertNull($this->redactor(new RecordingOptions(uri: false))->redact($this->activity())->uri);
        self::assertNull($this->redactor(new RecordingOptions(route: false))->redact($this->activity())->route);
        self::assertNull($this->redactor(new RecordingOptions(method: false))->redact($this->activity())->method);
        self::assertNull($this->redactor(new RecordingOptions(statusCode: false))->redact($this->activity())->statusCode);
        self::assertSame([], $this->redactor(new RecordingOptions(context: false))->redact($this->activity())->context);
        self::assertNull($this->redactor(new RecordingOptions(firewall: false))->redact($this->activity())->firewall);
        self::assertNull($this->redactor(new RecordingOptions(sessionId: false))->redact($this->activity())->sessionId);
        self::assertNull($this->redactor(new RecordingOptions(requestId: false))->redact($this->activity())->requestId);
    }

    public function testDisablingUriDoesNotAffectOtherFields(): void
    {
        $result = $this->redactor(new RecordingOptions(uri: false))->redact($this->activity());

        self::assertSame(ActivityType::HttpRequest, $result->type);
        self::assertSame('jane.doe', $result->userIdentifier);
        self::assertSame('app_dashboard', $result->route);
    }

    public function testActionIsNeverRedacted(): void
    {
        $activity = Activity::custom('export.completed', new \DateTimeImmutable());

        $result = $this->redactor(new RecordingOptions(context: false))->redact($activity);

        self::assertSame('export.completed', $result->action);
    }

    public function testIpAddressAnonymizeKeepsTheNetworkPrefix(): void
    {
        $ipv4 = $this->redactor(new RecordingOptions(ipAddress: 'anonymize'))
            ->redact($this->activity()->withIpAddress('203.0.113.42'))
            ->ipAddress;

        self::assertSame('203.0.113.0', $ipv4);

        $ipv6 = $this->redactor(new RecordingOptions(ipAddress: 'anonymize'))
            ->redact($this->activity()->withIpAddress('2001:db8::1234:5678'))
            ->ipAddress;

        // The last 8 bytes (a /64) are zeroed; the network prefix, the
        // first 8 bytes, survives.
        self::assertSame('2001:db8::', $ipv6);
    }

    public function testUserIdentifierHashIsStableAndKeyedBySecret(): void
    {
        $activity = $this->activity();

        $first = $this->redactor(new RecordingOptions(userIdentifier: 'hash'), 'secret-a')->redact($activity)->userIdentifier;
        $again = $this->redactor(new RecordingOptions(userIdentifier: 'hash'), 'secret-a')->redact($activity)->userIdentifier;
        $differentSecret = $this->redactor(new RecordingOptions(userIdentifier: 'hash'), 'secret-b')->redact($activity)->userIdentifier;

        self::assertSame($first, $again);
        self::assertNotSame($first, $differentSecret);
        self::assertSame(64, \strlen((string) $first));
        self::assertNotSame('jane.doe', $first);
    }

    public function testSessionIdIsHashedEvenWhenKept(): void
    {
        $activity = $this->activity();

        $result = $this->redactor(new RecordingOptions(sessionId: true), 'secret-a')->redact($activity);
        $again = $this->redactor(new RecordingOptions(sessionId: true), 'secret-a')->redact($activity);

        self::assertNotSame('raw-session-id', $result->sessionId);
        self::assertSame($result->sessionId, $again->sessionId);
        self::assertSame(64, \strlen((string) $result->sessionId));
    }

    public function testNullFieldsStayNullRegardlessOfMode(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $result = $this->redactor(new RecordingOptions(ipAddress: 'anonymize', userIdentifier: 'hash'))->redact($activity);

        self::assertNull($result->ipAddress);
        self::assertNull($result->userIdentifier);
        self::assertNull($result->sessionId);
    }
}
