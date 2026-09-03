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

namespace IQ2i\VigieBundle\Tests\Monolog;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Model\Subject;
use IQ2i\VigieBundle\Monolog\EcsDocument;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @phpstan-import-type EcsDocumentShape from EcsDocument
 */
final class EcsDocumentTest extends TestCase
{
    private const RECORDED_AT = '2026-08-21 10:00:01';

    /**
     * @return iterable<string, array{ActivityType, list<string>, list<string>, ?string, string}>
     */
    public static function classificationProvider(): iterable
    {
        yield 'http_request' => [ActivityType::HttpRequest, ['web'], ['access'], 'success', 'http_request'];
        yield 'login_success' => [ActivityType::LoginSuccess, ['authentication'], ['start'], 'success', 'login'];
        yield 'login_failure' => [ActivityType::LoginFailure, ['authentication'], ['start'], 'failure', 'login'];
        yield 'logout' => [ActivityType::Logout, ['authentication'], ['end'], 'success', 'logout'];
        yield 'switch_user' => [ActivityType::SwitchUser, ['authentication', 'iam'], ['start'], 'success', 'switch_user'];
        yield 'token_deauthenticated' => [ActivityType::TokenDeauthenticated, ['authentication'], ['end'], 'failure', 'token_deauthenticated'];
        yield 'access_denied' => [ActivityType::AccessDenied, ['authentication'], ['denied'], 'failure', 'access_denied'];
        yield 'password_changed' => [ActivityType::PasswordChanged, ['iam'], ['user', 'change'], 'success', 'password_changed'];
        yield 'roles_changed' => [ActivityType::RolesChanged, ['iam'], ['user', 'change'], 'success', 'roles_changed'];
        yield 'csrf_failure' => [ActivityType::CsrfFailure, ['web'], ['denied'], 'failure', 'csrf_failure'];
        yield 'custom' => [ActivityType::Custom, [], ['info'], null, 'custom'];
    }

    /**
     * @param list<string> $expectedCategory
     * @param list<string> $expectedEventType
     */
    #[DataProvider('classificationProvider')]
    public function testEventCategoryTypeOutcomeAndDefaultAction(ActivityType $activityType, array $expectedCategory, array $expectedEventType, ?string $outcome, string $action): void
    {
        $activity = ActivityType::Custom === $activityType
            ? Activity::custom('custom', new \DateTimeImmutable())
            : (ActivityType::HttpRequest === $activityType
                ? Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 200)
                : Activity::security($activityType, new \DateTimeImmutable()));

        $document = EcsDocument::fromActivity($activity, new \DateTimeImmutable(self::RECORDED_AT));

        self::assertSame($expectedCategory, $document['event']['category']);
        self::assertSame($expectedEventType, $document['event']['type']);
        self::assertSame($outcome, $document['event']['outcome'] ?? null);
        self::assertSame($action, $document['event']['action']);
    }

    public function testHttpRequestOutcomeIsFailureAboveThreeHundredNinetyNine(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 403),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('failure', $document['event']['outcome'] ?? null);
    }

    public function testAnExplicitActionOverridesTheTypeDefault(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable())->withAction('sso.login'),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('sso.login', $document['event']['action']);
    }

    public function testSwitchUserExitProducesAnEndEventType(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::security(ActivityType::SwitchUser, new \DateTimeImmutable(), context: ['direction' => 'exit']),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame(['end'], $document['event']['type']);
    }

    public function testAThrottledLoginFailureAddsADeniedEventType(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::security(ActivityType::LoginFailure, new \DateTimeImmutable(), context: ['throttled' => true]),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame(['start', 'denied'], $document['event']['type']);
    }

    public function testEventIdCreatedAndDatasetAreAlwaysPresent(): void
    {
        $activity = Activity::custom('export.completed', new \DateTimeImmutable('2026-08-21 10:00:00'));

        $document = EcsDocument::fromActivity($activity, new \DateTimeImmutable(self::RECORDED_AT));

        self::assertSame($activity->eventId, $document['event']['id']);
        self::assertSame('vigie.activity', $document['event']['dataset']);
        self::assertSame('event', $document['event']['kind']);
        self::assertStringStartsWith('2026-08-21T10:00:01', $document['event']['created']);
        self::assertStringStartsWith('2026-08-21T10:00:00', $document['@timestamp']);
    }

    public function testAPlainUserIdentifierMapsToUserName(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable(), userIdentifier: 'jane.doe'),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('jane.doe', $document['user']['name'] ?? null);
        self::assertArrayNotHasKey('hash', $document['user']);
        self::assertSame(['jane.doe'], $document['related']['user'] ?? null);
    }

    public function testAHashedUserIdentifierMapsToUserHash(): void
    {
        $hash = hash_hmac('sha256', 'jane.doe', 'secret');

        $document = EcsDocument::fromActivity(
            Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable(), userIdentifier: $hash),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame($hash, $document['user']['hash'] ?? null);
        self::assertArrayNotHasKey('name', $document['user']);
    }

    public function testImpersonatorContextMapsToUserEffectiveNameAndRelatedUser(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 200, userIdentifier: 'jane.doe', context: ['impersonator' => 'admin']),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('admin', $document['user']['effective']['name'] ?? null);
        self::assertContains('admin', $document['related']['user'] ?? []);
        self::assertContains('jane.doe', $document['related']['user'] ?? []);
    }

    public function testOriginalUserContextMapsToUserEffectiveNameWhenNoImpersonator(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::security(ActivityType::SwitchUser, new \DateTimeImmutable(), userIdentifier: 'jane.doe', context: ['direction' => 'enter', 'original_user' => 'admin']),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('admin', $document['user']['effective']['name'] ?? null);
    }

    public function testNoUserAtAllOmitsTheUserGroup(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 200),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertArrayNotHasKey('user', $document);
        self::assertArrayNotHasKey('related', $document);
    }

    public function testAValidIpProducesSourceIpAndRelatedIp(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 200, ipAddress: '203.0.113.42'),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('203.0.113.42', $document['source']['address'] ?? null);
        self::assertSame('203.0.113.42', $document['source']['ip'] ?? null);
        self::assertSame(['203.0.113.42'], $document['related']['ip'] ?? null);
    }

    public function testAnAnonymizedIpStillValidatesAsAnIp(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 200, ipAddress: '203.0.113.0'),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('203.0.113.0', $document['source']['ip'] ?? null);
    }

    public function testANonIpShapedAddressOnlyProducesSourceAddress(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 200, ipAddress: 'not-an-ip'),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('not-an-ip', $document['source']['address'] ?? null);
        self::assertArrayNotHasKey('ip', $document['source']);
        self::assertArrayNotHasKey('related', $document);
    }

    public function testUriIsSplitIntoUrlPathAndQuery(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin/orders?page=2&sort=desc', 200),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('/admin/orders', $document['url']['path'] ?? null);
        self::assertSame('page=2&sort=desc', $document['url']['query'] ?? null);
    }

    public function testAUriWithNoQueryStringOmitsUrlQuery(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin/orders', 200),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('/admin/orders', $document['url']['path'] ?? null);
        self::assertArrayNotHasKey('query', $document['url']);
    }

    public function testMethodAndRequestIdMapToHttpRequest(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'POST', '/x', 200, requestId: 'req-1'),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('POST', $document['http']['request']['method'] ?? null);
        self::assertSame('req-1', $document['http']['request']['id'] ?? null);
        self::assertSame(200, $document['http']['response']['status_code'] ?? null);
    }

    public function testRouteFirewallSessionIdAndSubjectMapToVigieNamespace(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(
                new \DateTimeImmutable(),
                'GET',
                '/admin',
                200,
                route: 'app_admin',
                firewall: 'main',
                sessionId: 'hashed-session',
                subject: new Subject('order', 42),
            ),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('app_admin', $document['vigie']['route'] ?? null);
        self::assertSame('main', $document['vigie']['firewall'] ?? null);
        self::assertSame('hashed-session', $document['vigie']['session_id'] ?? null);
        self::assertSame(['type' => 'order', 'id' => '42'], $document['vigie']['subject'] ?? null);
        self::assertSame('http_request', $document['vigie']['type']);
    }

    public function testContextIsCarriedUnderVigieContext(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::custom('export.completed', new \DateTimeImmutable(), context: ['rows' => 42]),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertEquals((object) ['rows' => 42], $document['vigie']['context'] ?? null);
    }

    public function testEmptyContextOmitsVigieContext(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 200),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertArrayNotHasKey('context', $document['vigie']);
    }

    public function testAnEnforcedRemediationMapsToVigieRemediation(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 403)->withRemediation('ban'),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('ban', $document['vigie']['remediation'] ?? null);
    }

    public function testNoRemediationOmitsVigieRemediation(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 200),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertArrayNotHasKey('remediation', $document['vigie']);
    }

    public function testAppAndEnvMapToService(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::custom('export.completed', new \DateTimeImmutable()),
            new \DateTimeImmutable(self::RECORDED_AT),
            'shop',
            'prod',
        );

        self::assertSame(['name' => 'shop', 'environment' => 'prod'], $document['service'] ?? null);
    }

    public function testNoAppOrEnvOmitsService(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::custom('export.completed', new \DateTimeImmutable()),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertArrayNotHasKey('service', $document);
    }

    public function testUserAgentMapsWhenPresent(): void
    {
        $document = EcsDocument::fromActivity(
            Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/x', 200, userAgent: 'curl/8'),
            new \DateTimeImmutable(self::RECORDED_AT),
        );

        self::assertSame('curl/8', $document['user_agent']['original'] ?? null);
    }

    public function testMessageForHttpRequestIncludesMethodUriAndStatus(): void
    {
        $message = EcsDocument::message(Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 403));

        self::assertSame('http_request GET /admin 403', $message);
    }

    public function testMessageForLoginFailureIncludesUserAndIp(): void
    {
        $message = EcsDocument::message(Activity::security(
            ActivityType::LoginFailure,
            new \DateTimeImmutable(),
            userIdentifier: 'jane.doe',
            ipAddress: '203.0.113.0',
        ));

        self::assertSame('login_failure jane.doe from 203.0.113.0', $message);
    }

    public function testMessageForCustomUsesTheAction(): void
    {
        $message = EcsDocument::message(Activity::custom('export.completed', new \DateTimeImmutable()));

        self::assertSame('export.completed', $message);
    }
}
