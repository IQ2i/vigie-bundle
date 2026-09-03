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

namespace IQ2i\VigieBundle\Tests\Command;

use IQ2i\VigieBundle\Command\SyncThreatDecisionsCommand;
use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use IQ2i\VigieBundle\Tests\Threat\FakeThreatProvider;
use IQ2i\VigieBundle\Threat\ThreatProviderException;
use IQ2i\VigieBundle\Threat\ThreatSyncBatch;
use IQ2i\VigieBundle\Threat\ThreatSynchronizer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class SyncThreatDecisionsCommandTest extends TestCase
{
    public function testItReportsFailureWhenNoProviderIsConfigured(): void
    {
        $synchronizer = new ThreatSynchronizer(null, new InMemoryThreatDecisionStore());
        $tester = new CommandTester(new SyncThreatDecisionsCommand($synchronizer));

        $status = $tester->execute([]);

        self::assertSame(Command::FAILURE, $status);
        self::assertStringContainsString('iq2i_vigie.threat.provider', $tester->getDisplay());
    }

    public function testASuccessfulSyncReportsItsCounts(): void
    {
        $provider = new FakeThreatProvider();
        $store = new InMemoryThreatDecisionStore();
        $provider->nextBatch = new ThreatSyncBatch(
            added: [new ThreatDecision('fake', '1', ThreatScope::ip(), '1.2.3.4', 'ban', new \DateTimeImmutable())],
            skipped: 2,
        );
        $synchronizer = new ThreatSynchronizer($provider, $store);

        $tester = new CommandTester(new SyncThreatDecisionsCommand($synchronizer));
        $status = $tester->execute([]);

        self::assertSame(Command::SUCCESS, $status);
        self::assertStringContainsString('fake', $tester->getDisplay());
        self::assertStringContainsString('startup sync', $tester->getDisplay());
        self::assertStringContainsString('1 added', $tester->getDisplay());
        self::assertStringContainsString('2 skipped', $tester->getDisplay());
    }

    public function testTheStartupOptionForcesAFullResync(): void
    {
        $provider = new FakeThreatProvider();
        $store = new InMemoryThreatDecisionStore();
        $synchronizer = new ThreatSynchronizer($provider, $store);

        $tester = new CommandTester(new SyncThreatDecisionsCommand($synchronizer));
        $tester->execute(['--startup' => true]);

        self::assertTrue($provider->calls[0]);
    }

    public function testTheNoPurgeOptionSkipsPurging(): void
    {
        $provider = new FakeThreatProvider();
        $store = new InMemoryThreatDecisionStore();
        $expired = new ThreatDecision('fake', '1', ThreatScope::ip(), '1.2.3.4', 'ban', new \DateTimeImmutable('-1 hour'), new \DateTimeImmutable('-1 minute'));
        $provider->nextBatch = new ThreatSyncBatch(added: [$expired]);
        $synchronizer = new ThreatSynchronizer($provider, $store);
        $synchronizer->sync();

        $provider->nextBatch = new ThreatSyncBatch();
        $tester = new CommandTester(new SyncThreatDecisionsCommand($synchronizer));
        $tester->execute(['--no-purge' => true]);

        self::assertStringContainsString('0 purged', $tester->getDisplay());
    }

    public function testAProviderFailureReportsAsFailureWithAReadableMessage(): void
    {
        $provider = new FakeThreatProvider();
        $provider->throws = new ThreatProviderException('the LAPI rejected the API key');
        $store = new InMemoryThreatDecisionStore();
        $synchronizer = new ThreatSynchronizer($provider, $store);

        $tester = new CommandTester(new SyncThreatDecisionsCommand($synchronizer));
        $status = $tester->execute([]);

        self::assertSame(Command::FAILURE, $status);
        self::assertStringContainsString('the LAPI rejected the API key', $tester->getDisplay());
    }
}
