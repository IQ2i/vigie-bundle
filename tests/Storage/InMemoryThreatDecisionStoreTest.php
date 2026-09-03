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
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use PHPUnit\Framework\TestCase;

final class InMemoryThreatDecisionStoreTest extends TestCase
{
    private function decision(string $externalId, ThreatScope $scope, string $value, ?\DateTimeImmutable $expiresAt = null, string $provider = 'crowdsec'): ThreatDecision
    {
        return new ThreatDecision($provider, $externalId, $scope, $value, 'ban', new \DateTimeImmutable('2026-08-21 10:00:00'), $expiresAt);
    }

    public function testApplyUpsertsAddedDecisions(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $decision = $this->decision('1', ThreatScope::ip(), '1.2.3.4');

        $store->apply('crowdsec', [$decision], [], new \DateTimeImmutable());

        self::assertCount(1, $store->find(new ThreatDecisionQuery()));
    }

    public function testApplyingTheSameDecisionTwiceDoesNotDuplicateIt(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $decision = $this->decision('1', ThreatScope::ip(), '1.2.3.4');

        $store->apply('crowdsec', [$decision], [], new \DateTimeImmutable());
        $store->apply('crowdsec', [$decision], [], new \DateTimeImmutable());

        self::assertSame(1, $store->count(new ThreatDecisionQuery()));
    }

    public function testApplyRemovesDecisionsByKeyBeforeAddingNewOnes(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $existing = $this->decision('1', ThreatScope::ip(), '1.2.3.4');
        $store->apply('crowdsec', [$existing], [], new \DateTimeImmutable());

        // The provider legitimately sends the same id in both "new" and
        // "deleted" — the re-added version must win.
        $renewed = $this->decision('1', ThreatScope::ip(), '5.6.7.8');
        $store->apply('crowdsec', [$renewed], [$existing], new \DateTimeImmutable());

        $remaining = $store->find(new ThreatDecisionQuery());
        self::assertCount(1, $remaining);
        self::assertSame('5.6.7.8', $remaining[0]->value);
    }

    public function testRemovingAnUnknownKeyIsANoOp(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $unknown = $this->decision('unknown', ThreatScope::ip(), '1.2.3.4');

        $store->apply('crowdsec', [], [$unknown], new \DateTimeImmutable());

        self::assertSame(0, $store->count(new ThreatDecisionQuery()));
    }

    public function testClearRemovesOnlyTheGivenProvidersDecisionsAndItsSyncTime(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::ip(), '1.2.3.4')], [], new \DateTimeImmutable());
        $store->apply('other', [$this->decision('1', ThreatScope::ip(), '5.6.7.8', provider: 'other')], [], new \DateTimeImmutable());

        $store->clear('crowdsec');

        self::assertSame(1, $store->count(new ThreatDecisionQuery()));
        self::assertNull($store->lastSyncedAt('crowdsec'));
        self::assertNotNull($store->lastSyncedAt('other'));
    }

    public function testLastSyncedAtReturnsNullWhenNeverSynced(): void
    {
        $store = new InMemoryThreatDecisionStore();

        self::assertNull($store->lastSyncedAt('crowdsec'));
    }

    public function testLastSyncedAtReturnsWhatWasApplied(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $syncedAt = new \DateTimeImmutable('2026-08-21 10:00:00');

        $store->apply('crowdsec', [], [], $syncedAt);

        self::assertEquals($syncedAt, $store->lastSyncedAt('crowdsec'));
    }

    public function testFindFiltersByScope(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            $this->decision('1', ThreatScope::ip(), '1.2.3.4'),
            $this->decision('2', ThreatScope::range(), '1.2.3.0/24'),
        ], [], new \DateTimeImmutable());

        $found = $store->find(new ThreatDecisionQuery(scopes: [ThreatScope::range()]));

        self::assertCount(1, $found);
        self::assertSame('1.2.3.0/24', $found[0]->value);
    }

    public function testFindFiltersByValue(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            $this->decision('1', ThreatScope::ip(), '1.2.3.4'),
            $this->decision('2', ThreatScope::ip(), '5.6.7.8'),
        ], [], new \DateTimeImmutable());

        $found = $store->find(new ThreatDecisionQuery(value: '5.6.7.8'));

        self::assertCount(1, $found);
        self::assertSame('5.6.7.8', $found[0]->value);
    }

    public function testFindMatchesAnIpAgainstADegenerateIpRange(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::ip(), '1.2.3.4')], [], new \DateTimeImmutable());

        self::assertCount(1, $store->find(new ThreatDecisionQuery(matchIp: '1.2.3.4')));
        self::assertCount(0, $store->find(new ThreatDecisionQuery(matchIp: '1.2.3.5')));
    }

    public function testFindMatchesAnIpInsideACidrRange(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::range(), '1.2.3.0/24')], [], new \DateTimeImmutable());

        self::assertCount(1, $store->find(new ThreatDecisionQuery(matchIp: '1.2.3.42')));
        self::assertCount(0, $store->find(new ThreatDecisionQuery(matchIp: '1.2.4.1')));
    }

    public function testFindNeverMatchesACustomScopeByIpEvenWhenItsValueLooksLikeOne(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::of('username'), '1.2.3.4')], [], new \DateTimeImmutable());

        self::assertCount(0, $store->find(new ThreatDecisionQuery(matchIp: '1.2.3.4')));
        self::assertCount(1, $store->find(new ThreatDecisionQuery(value: '1.2.3.4')));
    }

    public function testFindFiltersByProvider(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::ip(), '1.2.3.4')], [], new \DateTimeImmutable());
        $store->apply('other', [$this->decision('1', ThreatScope::ip(), '5.6.7.8', provider: 'other')], [], new \DateTimeImmutable());

        self::assertCount(1, $store->find(new ThreatDecisionQuery(provider: 'other')));
    }

    public function testFindFiltersOutExpiredDecisionsWhenActiveAtIsSet(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            $this->decision('1', ThreatScope::ip(), '1.2.3.4', new \DateTimeImmutable('2026-08-21 09:00:00')),
            $this->decision('2', ThreatScope::ip(), '5.6.7.8', new \DateTimeImmutable('2026-08-21 11:00:00')),
        ], [], new \DateTimeImmutable());

        $found = $store->find(new ThreatDecisionQuery(activeAt: new \DateTimeImmutable('2026-08-21 10:00:00')));

        self::assertCount(1, $found);
        self::assertSame('5.6.7.8', $found[0]->value);
    }

    public function testFindHonoursTheLimit(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            $this->decision('1', ThreatScope::ip(), '1.2.3.4'),
            $this->decision('2', ThreatScope::ip(), '5.6.7.8'),
        ], [], new \DateTimeImmutable());

        self::assertCount(1, $store->find(new ThreatDecisionQuery(limit: 1)));
    }

    public function testCountIgnoresTheLimit(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            $this->decision('1', ThreatScope::ip(), '1.2.3.4'),
            $this->decision('2', ThreatScope::ip(), '5.6.7.8'),
        ], [], new \DateTimeImmutable());

        self::assertSame(2, $store->count(new ThreatDecisionQuery(limit: 1)));
    }

    public function testPurgeExpiredDeletesOnlyExpiredDecisions(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            $this->decision('1', ThreatScope::ip(), '1.2.3.4', new \DateTimeImmutable('2026-08-21 09:00:00')),
            $this->decision('2', ThreatScope::ip(), '5.6.7.8', new \DateTimeImmutable('2026-08-21 11:00:00')),
            $this->decision('3', ThreatScope::ip(), '9.9.9.9'),
        ], [], new \DateTimeImmutable());

        $deleted = $store->purgeExpired(new \DateTimeImmutable('2026-08-21 10:00:00'), 1000);

        self::assertSame(1, $deleted);
        self::assertSame(2, $store->count(new ThreatDecisionQuery()));
    }

    public function testPurgeExpiredTreatsExpiresAtEqualToNowAsExpired(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $now = new \DateTimeImmutable('2026-08-21 10:00:00');
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::ip(), '1.2.3.4', $now)], [], new \DateTimeImmutable());

        $deleted = $store->purgeExpired($now, 1000);

        self::assertSame(1, $deleted);
    }
}
