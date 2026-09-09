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
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\FlockStore;
use Symfony\Component\Lock\Store\SemaphoreStore;

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

    /**
     * A run already holding the command's lock must be skipped rather than racing the in-progress one.
     */
    public function testAnAlreadyRunningInstanceIsSkipped(): void
    {
        $lock = self::lockFactory()->createLock('vigie:threat:sync');
        self::assertTrue($lock->acquire());

        try {
            $provider = new FakeThreatProvider();
            $synchronizer = new ThreatSynchronizer($provider, new InMemoryThreatDecisionStore());

            $tester = new CommandTester(new SyncThreatDecisionsCommand($synchronizer));
            $status = $tester->execute([]);

            self::assertSame(Command::SUCCESS, $status);
            self::assertSame([], $provider->calls, 'sync() must never run while another instance holds the lock.');
            self::assertStringContainsString('Another vigie:threat:sync is already running', $tester->getDisplay());
        } finally {
            $lock->release();
        }
    }

    /**
     * A lock left held after a run would make every subsequent run look like an overlap forever.
     */
    public function testTheLockIsReleasedAfterARun(): void
    {
        $provider = new FakeThreatProvider();
        $synchronizer = new ThreatSynchronizer($provider, new InMemoryThreatDecisionStore());

        (new CommandTester(new SyncThreatDecisionsCommand($synchronizer)))->execute([]);
        $status = (new CommandTester(new SyncThreatDecisionsCommand($synchronizer)))->execute([]);

        self::assertSame(Command::SUCCESS, $status);
        self::assertCount(2, $provider->calls);
    }

    public function testWatchLoopsUntilASignalArrivesAndOnlyForcesStartupOnTheFirstIteration(): void
    {
        $provider = new FakeThreatProvider();
        $synchronizer = new ThreatSynchronizer($provider, new InMemoryThreatDecisionStore());
        $sleeps = 0;
        // The signal is handled between two iterations (inside the sleep callback), so it takes
        // effect on the *second* sleep: iteration 1 (startup) runs, sleep, iteration 2 (delta) runs,
        // sleep (signal fires here), loop condition sees $stopping and exits before a third run.
        $command = new SyncThreatDecisionsCommand($synchronizer, static function () use (&$command, &$sleeps): void {
            if (++$sleeps >= 2) {
                \assert($command instanceof SyncThreatDecisionsCommand);
                $command->handleSignal(\SIGTERM);
            }
        });

        $tester = new CommandTester($command);
        $status = $tester->execute(['--watch' => true, '--startup' => true]);

        self::assertSame(Command::SUCCESS, $status);
        self::assertCount(2, $provider->calls);
        self::assertTrue($provider->calls[0]);
        self::assertFalse($provider->calls[1], 'Only the first --watch iteration should force a startup resync.');
    }

    public function testWatchStaysSilentWhenAnIterationChangesNothing(): void
    {
        $provider = new FakeThreatProvider();
        $store = new InMemoryThreatDecisionStore();
        $synchronizer = new ThreatSynchronizer($provider, $store);
        // Seeds lastSyncedAt so the command's own run below is a delta, not an implicit first-ever startup.
        $synchronizer->sync();
        $provider->calls = [];

        $command = new SyncThreatDecisionsCommand($synchronizer, static function () use (&$command): void {
            \assert($command instanceof SyncThreatDecisionsCommand);
            $command->handleSignal(\SIGTERM);
        });

        $tester = new CommandTester($command);
        $tester->execute(['--watch' => true]);

        self::assertSame('', trim($tester->getDisplay()));
    }

    public function testWatchStillReportsAnIterationThatChangedSomething(): void
    {
        $provider = new FakeThreatProvider();
        $provider->nextBatch = new ThreatSyncBatch(added: [
            new ThreatDecision('fake', '1', ThreatScope::ip(), '1.2.3.4', 'ban', new \DateTimeImmutable()),
        ]);
        $synchronizer = new ThreatSynchronizer($provider, new InMemoryThreatDecisionStore());
        $command = new SyncThreatDecisionsCommand($synchronizer, static function () use (&$command): void {
            \assert($command instanceof SyncThreatDecisionsCommand);
            $command->handleSignal(\SIGTERM);
        });

        $tester = new CommandTester($command);
        $tester->execute(['--watch' => true]);

        self::assertStringContainsString('1 added', $tester->getDisplay());
    }

    public function testWatchStopsOnAFailureWithoutLoopingFurther(): void
    {
        $provider = new FakeThreatProvider();
        $provider->throws = new ThreatProviderException('the LAPI rejected the API key');
        $synchronizer = new ThreatSynchronizer($provider, new InMemoryThreatDecisionStore());
        $sleepCalls = 0;
        $command = new SyncThreatDecisionsCommand($synchronizer, static function () use (&$sleepCalls): void {
            ++$sleepCalls;
        });

        $tester = new CommandTester($command);
        $status = $tester->execute(['--watch' => true]);

        self::assertSame(Command::FAILURE, $status);
        self::assertSame(0, $sleepCalls);
        self::assertCount(1, $provider->calls);
    }

    public function testAnOutOfRangeIntervalIsInvalid(): void
    {
        $provider = new FakeThreatProvider();
        $synchronizer = new ThreatSynchronizer($provider, new InMemoryThreatDecisionStore());

        $tester = new CommandTester(new SyncThreatDecisionsCommand($synchronizer));
        $status = $tester->execute(['--watch' => true, '--interval' => '0']);

        self::assertSame(Command::INVALID, $status);
        self::assertStringContainsString('--interval', $tester->getDisplay());
    }

    public function testWithoutWatchTheIntervalOptionIsIgnored(): void
    {
        $provider = new FakeThreatProvider();
        $synchronizer = new ThreatSynchronizer($provider, new InMemoryThreatDecisionStore());

        $tester = new CommandTester(new SyncThreatDecisionsCommand($synchronizer));
        $status = $tester->execute([]);

        self::assertSame(Command::SUCCESS, $status);
        self::assertCount(1, $provider->calls);
    }

    public function testTheLockCoversTheWholeWatchSessionNotEachIteration(): void
    {
        $provider = new FakeThreatProvider();
        $synchronizer = new ThreatSynchronizer($provider, new InMemoryThreatDecisionStore());
        $command = new SyncThreatDecisionsCommand($synchronizer, static function () use (&$command): void {
            // While a --watch run is sleeping between two iterations, its own lock must still be held:
            // a second instance must be skipped, not race it.
            $second = new CommandTester(new SyncThreatDecisionsCommand(new ThreatSynchronizer(new FakeThreatProvider(), new InMemoryThreatDecisionStore())));
            $second->execute([]);
            self::assertStringContainsString('Another vigie:threat:sync is already running', $second->getDisplay());

            \assert($command instanceof SyncThreatDecisionsCommand);
            $command->handleSignal(\SIGTERM);
        });

        $tester = new CommandTester($command);
        $tester->execute(['--watch' => true]);
    }

    /**
     * Mirrors the default store LockableTrait itself falls back to when no LockFactory is injected.
     */
    private static function lockFactory(): LockFactory
    {
        return new LockFactory(SemaphoreStore::isSupported() ? new SemaphoreStore() : new FlockStore());
    }
}
