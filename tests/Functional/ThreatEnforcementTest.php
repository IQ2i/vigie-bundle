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

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;

final class ThreatEnforcementTest extends FunctionalTestCase
{
    public function testABannedIpGetsA403AndTheRecordedActivityCarriesTheRemediation(): void
    {
        $client = self::createClient(['environment' => 'threat_enforce']);
        $client->disableReboot();

        /** @var ThreatDecisionStoreInterface $store */
        $store = self::getContainer()->get(ThreatDecisionStoreInterface::class);
        $store->apply('seed', [
            new ThreatDecision('seed', '1', ThreatScope::ip(), '127.0.0.1', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $client->request('GET', '/ping');

        self::assertSame(403, $client->getResponse()->getStatusCode());

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertSame('ban', $activities[0]->remediation);
    }

    public function testACaptchaDecisionRedirectsToTheConfiguredRouteWhichIsItselfServed(): void
    {
        $client = self::createClient(['environment' => 'threat_enforce']);
        $client->disableReboot();

        /** @var ThreatDecisionStoreInterface $store */
        $store = self::getContainer()->get(ThreatDecisionStoreInterface::class);
        $store->apply('seed', [
            new ThreatDecision('seed', '1', ThreatScope::ip(), '127.0.0.1', 'captcha', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $client->request('GET', '/ping');

        self::assertSame(302, $client->getResponse()->getStatusCode());
        self::assertSame('/captcha', $client->getResponse()->headers->get('Location'));

        $client->request('GET', '/captcha');

        self::assertSame(200, $client->getResponse()->getStatusCode());
    }
}
