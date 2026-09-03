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

namespace IQ2i\VigieBundle\Tests\Functional;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;

final class SecurityFlowTest extends FunctionalTestCase
{
    public function testAFailedLoginIsRecordedWithTheFirewallAndReason(): void
    {
        $client = static::createClient(['environment' => 'security']);

        $client->request('GET', '/protected', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'wrong-password']);

        self::assertSame(401, $client->getResponse()->getStatusCode());

        $activities = $this->findActivities(ActivityType::LoginFailure);

        self::assertCount(1, $activities);
        self::assertSame('jane.doe', $activities[0]->userIdentifier);
        self::assertSame('main', $activities[0]->firewall);
        self::assertArrayHasKey('reason', $activities[0]->context);
    }

    public function testASuccessfulLoginIsRecordedAndTheRequestSucceeds(): void
    {
        $client = static::createClient(['environment' => 'security']);

        $client->request('GET', '/protected', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'password']);

        self::assertSame(200, $client->getResponse()->getStatusCode());

        /** @var array{user: ?string} $body */
        $body = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertSame('jane.doe', $body['user']);

        $activities = $this->findActivities(ActivityType::LoginSuccess);

        self::assertCount(1, $activities);
        self::assertSame('jane.doe', $activities[0]->userIdentifier);
        self::assertSame('main', $activities[0]->firewall);
    }

    public function testASwitchUserIsRecordedWithTheOriginalUser(): void
    {
        $client = static::createClient(['environment' => 'security']);

        $client->request('GET', '/protected?_switch_user=jane.doe', server: ['PHP_AUTH_USER' => 'admin', 'PHP_AUTH_PW' => 'password']);

        // Symfony's switch_user listener redirects to the same URL stripped
        // of "_switch_user" once impersonation succeeds; a failed one
        // responds 403 instead, so the redirect itself is the success signal.
        self::assertSame(302, $client->getResponse()->getStatusCode());

        $activities = $this->findActivities(ActivityType::SwitchUser);

        self::assertCount(1, $activities);
        self::assertSame('jane.doe', $activities[0]->userIdentifier);
        self::assertSame('enter', $activities[0]->context['direction'] ?? null);
        self::assertSame('admin', $activities[0]->context['original_user'] ?? null);
    }

    public function testALogoutIsRecordedWithTheFirewallAndUser(): void
    {
        $client = static::createClient(['environment' => 'security']);
        $client->disableReboot();

        $client->request('GET', '/protected', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'password']);
        self::assertSame(200, $client->getResponse()->getStatusCode());

        // http_basic re-authenticates from the header on every request
        // rather than persisting the token in the session; the header
        // must still be present for the logout listener to see a token to
        // log out at all.
        $client->request('GET', '/logout', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'password']);

        // Symfony's logout listener redirects to the configured target
        // ("/" by default) once the session is cleared.
        self::assertSame(302, $client->getResponse()->getStatusCode());

        $activities = $this->findActivities(ActivityType::Logout);

        self::assertCount(1, $activities);
        self::assertSame('jane.doe', $activities[0]->userIdentifier);
        self::assertSame('main', $activities[0]->firewall);
    }

    // The "exit" direction is covered at the unit level by SecurityActivitySubscriberTest::testSwitchUserExitDoesNotReportAnOriginalUser — this micro test kernel doesn't persist sessions across requests.

    public function testTheRequestIdCorrelatesTheHttpRequestAndTheLoginFailureActivities(): void
    {
        $client = static::createClient(['environment' => 'security']);

        $client->request('GET', '/protected', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'wrong-password']);

        $httpRequests = $this->findActivities(ActivityType::HttpRequest);
        $loginFailures = $this->findActivities(ActivityType::LoginFailure);

        self::assertCount(1, $httpRequests);
        self::assertCount(1, $loginFailures);
        self::assertNotNull($httpRequests[0]->requestId);
        self::assertSame($httpRequests[0]->requestId, $loginFailures[0]->requestId);
    }

    public function testAccessDeniedIsRecordedAlongsideTheForbiddenHttpRequest(): void
    {
        $client = static::createClient(['environment' => 'security']);

        $client->request('GET', '/protected/forbidden', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'password']);

        self::assertSame(403, $client->getResponse()->getStatusCode());

        $accessDenied = $this->findActivities(ActivityType::AccessDenied);
        $httpRequests = $this->findActivities(ActivityType::HttpRequest);

        self::assertCount(1, $accessDenied);
        self::assertSame('jane.doe', $accessDenied[0]->userIdentifier);
        self::assertSame('main', $accessDenied[0]->firewall);
        self::assertSame('ROLE_ADMIN', $accessDenied[0]->context['attributes'] ?? null);

        self::assertCount(1, $httpRequests);
        self::assertSame(403, $httpRequests[0]->statusCode);
        self::assertNotNull($accessDenied[0]->requestId);
        self::assertSame($httpRequests[0]->requestId, $accessDenied[0]->requestId);
    }

    /**
     * @return list<Activity>
     */
    private function findActivities(ActivityType $type): array
    {
        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        return array_values(array_filter($storage->all(), static fn (Activity $activity): bool => $type === $activity->type));
    }
}
