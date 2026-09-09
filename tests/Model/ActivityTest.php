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

namespace IQ2i\VigieBundle\Tests\Model;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Model\Subject;
use PHPUnit\Framework\TestCase;

final class ActivityTest extends TestCase
{
    public function testHttpRequestNamedConstructor(): void
    {
        $occurredAt = new \DateTimeImmutable('2026-08-21 10:00:00');

        $activity = Activity::httpRequest(
            occurredAt: $occurredAt,
            method: 'GET',
            uri: '/dashboard',
            route: 'app_dashboard',
            statusCode: 200,
            userIdentifier: 'jane.doe',
            ipAddress: '127.0.0.1',
            userAgent: 'Symfony',
        );

        self::assertSame(ActivityType::HttpRequest, $activity->type);
        self::assertSame($occurredAt, $activity->occurredAt);
        self::assertSame('GET', $activity->method);
        self::assertSame('/dashboard', $activity->uri);
        self::assertSame('app_dashboard', $activity->route);
        self::assertSame(200, $activity->statusCode);
        self::assertSame('jane.doe', $activity->userIdentifier);
        self::assertSame('127.0.0.1', $activity->ipAddress);
        self::assertSame('Symfony', $activity->userAgent);
    }

    public function testSecurityNamedConstructor(): void
    {
        $occurredAt = new \DateTimeImmutable('2026-08-21 10:00:00');

        $activity = Activity::security(
            type: ActivityType::LoginFailure,
            occurredAt: $occurredAt,
            userIdentifier: 'jane.doe',
            ipAddress: '127.0.0.1',
            context: ['reason' => 'invalid_credentials'],
        );

        self::assertSame(ActivityType::LoginFailure, $activity->type);
        self::assertNull($activity->method);
        self::assertNull($activity->uri);
        self::assertNull($activity->statusCode);
        self::assertSame(['reason' => 'invalid_credentials'], $activity->context);
    }

    public function testSecurityRejectsCustomAndHttpRequestTypes(): void
    {
        $occurredAt = new \DateTimeImmutable('2026-08-21 10:00:00');

        $this->expectException(\InvalidArgumentException::class);

        Activity::security(type: ActivityType::Custom, occurredAt: $occurredAt);
    }

    public function testSecurityRejectsHttpRequestType(): void
    {
        $occurredAt = new \DateTimeImmutable('2026-08-21 10:00:00');

        $this->expectException(\InvalidArgumentException::class);

        Activity::security(type: ActivityType::HttpRequest, occurredAt: $occurredAt);
    }

    public function testCustomNamedConstructor(): void
    {
        $occurredAt = new \DateTimeImmutable('2026-08-21 10:00:00');

        $activity = Activity::custom(
            action: 'export.completed',
            occurredAt: $occurredAt,
            userIdentifier: 'jane.doe',
            context: ['rows' => 42],
        );

        self::assertSame(ActivityType::Custom, $activity->type);
        self::assertSame('export.completed', $activity->action);
        self::assertSame('jane.doe', $activity->userIdentifier);
        self::assertSame(['rows' => 42], $activity->context);
        self::assertNull($activity->method);
        self::assertNull($activity->uri);
    }

    public function testEmptyStringsAreNormalizedToNull(): void
    {
        $activity = new Activity(
            type: ActivityType::HttpRequest,
            occurredAt: new \DateTimeImmutable(),
            action: '',
            userIdentifier: '',
            ipAddress: '',
            userAgent: '',
            route: '',
            firewall: '',
            sessionId: '',
            requestId: '',
            remediation: '',
        );

        self::assertNull($activity->action);
        self::assertNull($activity->userIdentifier);
        self::assertNull($activity->ipAddress);
        self::assertNull($activity->userAgent);
        self::assertNull($activity->route);
        self::assertNull($activity->firewall);
        self::assertNull($activity->sessionId);
        self::assertNull($activity->requestId);
        self::assertNull($activity->remediation);
    }

    public function testNonScalarContextValuesAreDropped(): void
    {
        $activity = new Activity(
            type: ActivityType::Custom,
            occurredAt: new \DateTimeImmutable(),
            context: [
                'kept' => 'value',
                'also_kept' => null,
                'dropped_array' => ['nested' => true],
                'dropped_object' => new \stdClass(),
            ],
        );

        self::assertSame(['kept' => 'value', 'also_kept' => null], $activity->context);
    }

    public function testAnEventIdIsMintedWhenNoneIsGiven(): void
    {
        $activity = Activity::custom('export.completed', new \DateTimeImmutable());

        self::assertNotSame('', $activity->eventId);
    }

    public function testTwoActivitiesGetDifferentEventIds(): void
    {
        $now = new \DateTimeImmutable();

        $first = Activity::custom('export.completed', $now);
        $second = Activity::custom('export.completed', $now);

        self::assertNotSame($first->eventId, $second->eventId);
    }

    public function testAnExplicitEventIdIsPreserved(): void
    {
        $activity = new Activity(
            type: ActivityType::Custom,
            occurredAt: new \DateTimeImmutable(),
            action: 'export.completed',
            eventId: '11111111-1111-7111-8111-111111111111',
        );

        self::assertSame('11111111-1111-7111-8111-111111111111', $activity->eventId);
    }

    public function testWithersOtherThanWithEventIdCarryTheEventIdOverUnchanged(): void
    {
        $original = Activity::custom('export.completed', new \DateTimeImmutable());

        self::assertSame($original->eventId, $original->withAction('other')->eventId);
    }

    public function testFirewallIsCarried(): void
    {
        $activity = Activity::httpRequest(
            occurredAt: new \DateTimeImmutable(),
            method: 'GET',
            uri: '/admin',
            route: 'app_admin',
            statusCode: 200,
            firewall: 'admin',
        );

        self::assertSame('admin', $activity->firewall);
    }

    public function testWithersReturnANewInstanceWithOnlyTheTargetedFieldChanged(): void
    {
        $original = Activity::httpRequest(
            occurredAt: new \DateTimeImmutable('2026-08-21 10:00:00'),
            method: 'GET',
            uri: '/dashboard',
            route: 'app_dashboard',
            statusCode: 200,
            userIdentifier: 'jane.doe',
            ipAddress: '203.0.113.1',
            userAgent: 'Symfony',
            context: ['a' => 1],
            firewall: 'main',
        );

        $withIp = $original->withIpAddress('203.0.113.2');

        self::assertNotSame($original, $withIp);
        self::assertSame('203.0.113.1', $original->ipAddress);
        self::assertSame('203.0.113.2', $withIp->ipAddress);
        self::assertSame($original->userIdentifier, $withIp->userIdentifier);
        self::assertSame($original->userAgent, $withIp->userAgent);
        self::assertSame($original->route, $withIp->route);
        self::assertSame($original->statusCode, $withIp->statusCode);
        self::assertSame($original->context, $withIp->context);
        self::assertSame($original->firewall, $withIp->firewall);
        self::assertSame($original->occurredAt, $withIp->occurredAt);

        self::assertSame('john.doe', $original->withUserIdentifier('john.doe')->userIdentifier);
        self::assertNull($original->withUserIdentifier('john.doe')->withUserIdentifier(null)->userIdentifier);
        self::assertNull($original->withUserAgent(null)->userAgent);
        self::assertSame('exported', $original->withAction('exported')->action);
        self::assertSame('/other', $original->withUri('/other')->uri);
        self::assertSame('app_other', $original->withRoute('app_other')->route);
        self::assertSame(500, $original->withStatusCode(500)->statusCode);
        self::assertSame('other', $original->withFirewall('other')->firewall);
        self::assertSame('sess-1', $original->withSessionId('sess-1')->sessionId);
        self::assertSame('req-1', $original->withRequestId('req-1')->requestId);
        self::assertSame(['b' => 2], $original->withContext(['b' => 2])->context);
        self::assertSame(['a' => 1, 'b' => 2], $original->withAddedContext(['b' => 2])->context);
        self::assertSame('11111111-1111-7111-8111-111111111111', $original->withEventId('11111111-1111-7111-8111-111111111111')->eventId);
        self::assertSame('ban', $original->withRemediation('ban')->remediation);
        self::assertNull($original->withRemediation('ban')->withRemediation(null)->remediation);

        $subject = new Subject('user', 42);
        self::assertSame($subject, $original->withSubject($subject)->subject);
        self::assertNull($original->withSubject($subject)->withSubject(null)->subject);
    }

    public function testNamedConstructorsCarryTheSubject(): void
    {
        $subject = new Subject('user', 42);

        self::assertSame($subject, Activity::httpRequest(
            occurredAt: new \DateTimeImmutable(),
            method: 'GET',
            uri: '/dashboard',
            statusCode: 200,
            subject: $subject,
        )->subject);

        self::assertSame($subject, Activity::security(
            type: ActivityType::LoginSuccess,
            occurredAt: new \DateTimeImmutable(),
            subject: $subject,
        )->subject);

        self::assertSame($subject, Activity::custom(
            action: 'export.completed',
            occurredAt: new \DateTimeImmutable(),
            subject: $subject,
        )->subject);
    }
}
