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
use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;

/**
 * Proves the network stage of ThreatEnforcementSubscriber runs above the firewall: without it, an
 * authenticator (here HttpBasicAuthenticator, whose onAuthenticationFailure/onAuthenticationSuccess
 * both set a response of their own) would set a response and stop kernel.request propagation before
 * a request-priority-7 subscriber ever got a chance to run, letting a banned IP authenticate freely.
 */
final class ThreatEnforcementLoginTest extends FunctionalTestCase
{
    private function seedIpBan(): void
    {
        /** @var ThreatDecisionStoreInterface $store */
        $store = self::getContainer()->get(ThreatDecisionStoreInterface::class);
        $store->apply('seed', [
            new ThreatDecision('seed', '1', ThreatScope::ip(), '127.0.0.1', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());
    }

    public function testABannedIpNeverReachesTheAuthenticatorOnAFailedLogin(): void
    {
        $client = self::createClient(['environment' => 'threat_enforce_security']);
        $client->disableReboot();

        $this->seedIpBan();

        $client->request('GET', '/protected', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'wrong-password']);

        self::assertSame(403, $client->getResponse()->getStatusCode());
        self::assertEmpty($this->findActivities(ActivityType::LoginFailure));

        $httpRequests = $this->findActivities(ActivityType::HttpRequest);
        self::assertCount(1, $httpRequests);
        self::assertSame('ban', $httpRequests[0]->remediation);
    }

    public function testABannedIpNeverReachesTheAuthenticatorOnASuccessfulLogin(): void
    {
        $client = self::createClient(['environment' => 'threat_enforce_security']);
        $client->disableReboot();

        $this->seedIpBan();

        $client->request('GET', '/protected', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'password']);

        self::assertSame(403, $client->getResponse()->getStatusCode());
        self::assertEmpty($this->findActivities(ActivityType::LoginSuccess));
    }

    public function testAnUnbannedIpStillAuthenticatesNormally(): void
    {
        $client = self::createClient(['environment' => 'threat_enforce_security']);

        $client->request('GET', '/protected', server: ['PHP_AUTH_USER' => 'jane.doe', 'PHP_AUTH_PW' => 'password']);

        self::assertSame(200, $client->getResponse()->getStatusCode());
        self::assertCount(1, $this->findActivities(ActivityType::LoginSuccess));
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
