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

use IQ2i\VigieBundle\Event\ThreatDecisionsSynced;
use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use IQ2i\VigieBundle\Threat\ThreatProviderException;
use IQ2i\VigieBundle\Threat\ThreatSyncBatch;
use IQ2i\VigieBundle\Threat\ThreatSynchronizer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;

final class ThreatSynchronizerTest extends TestCase
{
    private FakeThreatProvider $provider;
    private InMemoryThreatDecisionStore $store;

    protected function setUp(): void
    {
        $this->provider = new FakeThreatProvider();
        $this->store = new InMemoryThreatDecisionStore();
    }

    private function decision(string $externalId, string $value = '1.2.3.4'): ThreatDecision
    {
        return new ThreatDecision('fake', $externalId, ThreatScope::ip(), $value, 'ban', new \DateTimeImmutable());
    }

    private function synchronizer(?EventDispatcher $dispatcher = null): ThreatSynchronizer
    {
        return new ThreatSynchronizer($this->provider, $this->store, $dispatcher);
    }

    public function testAnEmptyStoreTriggersAStartupSync(): void
    {
        $report = $this->synchronizer()->sync();

        self::assertTrue($report['startup']);
        self::assertTrue($this->provider->calls[0]);
    }

    public function testAPopulatedStoreDoesNotTriggerAStartupSync(): void
    {
        $synchronizer = $this->synchronizer();

        $this->provider->nextBatch = new ThreatSyncBatch(added: [$this->decision('1')]);
        $synchronizer->sync(); // first run: startup, populates the store

        $this->provider->nextBatch = new ThreatSyncBatch(added: [$this->decision('2', '5.6.7.8')]);
        $report = $synchronizer->sync();

        self::assertFalse($report['startup']);
    }

    public function testForceStartupClearsTheStoreBeforeApplying(): void
    {
        $synchronizer = $this->synchronizer();

        $this->provider->nextBatch = new ThreatSyncBatch(added: [$this->decision('1')]);
        $synchronizer->sync();
        self::assertSame(1, $this->store->count(new ThreatDecisionQuery()));

        $this->provider->nextBatch = new ThreatSyncBatch(); // a startup batch with nothing active anymore
        $report = $synchronizer->sync(forceStartup: true);

        self::assertTrue($report['startup']);
        self::assertSame(0, $this->store->count(new ThreatDecisionQuery()));
    }

    public function testRemovedDecisionsAreAppliedBeforeAddedOnes(): void
    {
        $synchronizer = $this->synchronizer();

        $existing = $this->decision('1', '1.2.3.4');
        $this->provider->nextBatch = new ThreatSyncBatch(added: [$existing]);
        $synchronizer->sync();

        // The same id re-issued with a new value must win over its own removal.
        $renewed = $this->decision('1', '5.6.7.8');
        $this->provider->nextBatch = new ThreatSyncBatch(added: [$renewed], removed: [$existing]);
        $synchronizer->sync();

        $found = $this->store->find(new ThreatDecisionQuery());
        self::assertCount(1, $found);
        self::assertSame('5.6.7.8', $found[0]->value);
    }

    public function testPurgeExpiredIsCalledUnlessSkipped(): void
    {
        $synchronizer = $this->synchronizer();

        $expired = new ThreatDecision('fake', '1', ThreatScope::ip(), '1.2.3.4', 'ban', new \DateTimeImmutable('-1 hour'), new \DateTimeImmutable('-1 minute'));
        $this->provider->nextBatch = new ThreatSyncBatch(added: [$expired]);
        $synchronizer->sync();

        self::assertSame(0, $synchronizer->sync(purge: false)['purged']);
        self::assertSame(1, $synchronizer->sync(purge: true)['purged']);
    }

    public function testTheEventReflectsAStartupRunOnFirstSync(): void
    {
        $dispatcher = new EventDispatcher();
        $observed = null;
        $dispatcher->addListener(ThreatDecisionsSynced::class, static function (ThreatDecisionsSynced $event) use (&$observed): void {
            $observed = $event;
        });
        $synchronizer = $this->synchronizer($dispatcher);

        $decision = $this->decision('1');
        $this->provider->nextBatch = new ThreatSyncBatch(added: [$decision]);
        $synchronizer->sync();

        self::assertInstanceOf(ThreatDecisionsSynced::class, $observed);
        self::assertTrue($observed->startup);
        self::assertSame([$decision], $observed->added);
        self::assertSame('fake', $observed->provider);
    }

    public function testAProviderExceptionPropagates(): void
    {
        $this->provider->throws = new ThreatProviderException('boom');

        $this->expectException(ThreatProviderException::class);
        $this->expectExceptionMessage('boom');

        $this->synchronizer()->sync();
    }

    public function testAProviderDownDuringAStartupRunLeavesThePreviousDecisionsInPlace(): void
    {
        $synchronizer = $this->synchronizer();

        $this->provider->nextBatch = new ThreatSyncBatch(added: [$this->decision('1')]);
        $synchronizer->sync();

        $this->provider->throws = new ThreatProviderException('LAPI is down');

        try {
            $synchronizer->sync(forceStartup: true);
            self::fail('The provider exception should have propagated.');
        } catch (ThreatProviderException) {
        }

        self::assertSame(1, $this->store->count(new ThreatDecisionQuery()));
        self::assertNotNull($this->store->lastSyncedAt('fake'));
    }

    public function testASkippedCountIsReported(): void
    {
        $this->provider->nextBatch = new ThreatSyncBatch(skipped: 3);

        self::assertSame(3, $this->synchronizer()->sync()['skipped']);
    }

    public function testAListenerThatThrowsDoesNotFailTheSync(): void
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener(ThreatDecisionsSynced::class, static function (): never {
            throw new \RuntimeException('listener exploded');
        });

        $report = $this->synchronizer($dispatcher)->sync();

        self::assertTrue($report['startup']);
    }

    public function testSyncWithoutAProviderIsRejected(): void
    {
        $synchronizer = new ThreatSynchronizer(null, $this->store);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('iq2i_vigie.threat.provider');

        $synchronizer->sync();
    }

    public function testApplyBatchWorksWithoutAProvider(): void
    {
        $synchronizer = new ThreatSynchronizer(null, $this->store);

        $decision = $this->decision('1');
        $startupReport = $synchronizer->applyBatch('pushed', new ThreatSyncBatch(added: [$decision]), startup: true);

        self::assertSame('pushed', $startupReport['provider']);
        self::assertTrue($startupReport['startup']);
        self::assertSame(1, $startupReport['added']);
        self::assertCount(1, $this->store->find(new ThreatDecisionQuery()));

        $deltaReport = $synchronizer->applyBatch('pushed', new ThreatSyncBatch(removed: [$decision]), startup: false);

        self::assertFalse($deltaReport['startup']);
        self::assertSame(1, $deltaReport['removed']);
        self::assertCount(0, $this->store->find(new ThreatDecisionQuery()));
    }
}
