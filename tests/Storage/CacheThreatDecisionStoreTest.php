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

namespace IQ2i\VigieBundle\Tests\Storage;

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\CacheThreatDecisionStore;
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class CacheThreatDecisionStoreTest extends TestCase
{
    private function decision(string $externalId, ThreatScope $scope, string $value, string $provider = 'crowdsec'): ThreatDecision
    {
        return new ThreatDecision($provider, $externalId, $scope, $value, 'ban', new \DateTimeImmutable('2026-08-21 10:00:00'));
    }

    public function testApplyFindAndClearRoundTripThroughThePool(): void
    {
        $store = new CacheThreatDecisionStore(new ArrayAdapter());
        $syncedAt = new \DateTimeImmutable('2026-08-21 10:00:00');
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::ip(), '1.2.3.4')], [], $syncedAt);

        self::assertCount(1, $store->find(new ThreatDecisionQuery()));
        self::assertEquals($syncedAt, $store->lastSyncedAt('crowdsec'));

        $store->clear('crowdsec');

        self::assertSame(0, $store->count(new ThreatDecisionQuery()));
        self::assertNull($store->lastSyncedAt('crowdsec'));
    }

    public function testFindWithNoProviderScansEveryKnownProvider(): void
    {
        $store = new CacheThreatDecisionStore(new ArrayAdapter());
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::ip(), '1.2.3.4')], [], new \DateTimeImmutable());
        $store->apply('other', [$this->decision('1', ThreatScope::ip(), '5.6.7.8', provider: 'other')], [], new \DateTimeImmutable());

        self::assertCount(2, $store->find(new ThreatDecisionQuery()));
    }

    public function testAProviderNameOutsideThePsr6SafeAlphabetStillWorks(): void
    {
        $store = new CacheThreatDecisionStore(new ArrayAdapter());
        $provider = 'a/weird{provider}(name)';

        $store->apply($provider, [$this->decision('1', ThreatScope::ip(), '1.2.3.4', provider: $provider)], [], new \DateTimeImmutable());

        self::assertSame(1, $store->count(new ThreatDecisionQuery(provider: $provider)));
    }
}
