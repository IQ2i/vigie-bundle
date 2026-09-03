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

use IQ2i\VigieBundle\Command\ListThreatDecisionsCommand;
use IQ2i\VigieBundle\Command\SyncThreatDecisionsCommand;
use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\CacheThreatDecisionStore;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;
use IQ2i\VigieBundle\Tests\TestApplication\StaticThreatProvider;
use IQ2i\VigieBundle\Tests\TestApplication\ThreatCheckerHolder;
use IQ2i\VigieBundle\Threat\ThreatSubject;
use IQ2i\VigieBundle\Threat\ThreatSyncBatch;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Contracts\Service\ResetInterface;

final class ThreatCacheStoreTest extends FunctionalTestCase
{
    public function testTheCacheStoreIsResolvedByDefault(): void
    {
        self::bootKernel(['environment' => 'threat_cache']);

        self::assertInstanceOf(CacheThreatDecisionStore::class, self::getContainer()->get(ThreatDecisionStoreInterface::class));
    }

    public function testSyncWritesToTheCacheAndListReadsItBack(): void
    {
        self::bootKernel(['environment' => 'threat_cache']);

        /** @var StaticThreatProvider $provider */
        $provider = self::getContainer()->get(StaticThreatProvider::class);
        $provider->nextBatch = new ThreatSyncBatch(added: [
            new ThreatDecision('static', '1', ThreatScope::ip(), '1.2.3.4', 'ban', new \DateTimeImmutable()),
        ]);

        /** @var SyncThreatDecisionsCommand $syncCommand */
        $syncCommand = self::getContainer()->get(SyncThreatDecisionsCommand::class);
        $syncTester = new CommandTester($syncCommand);
        $status = $syncTester->execute([]);

        self::assertSame(Command::SUCCESS, $status);
        self::assertStringContainsString('1 added', $syncTester->getDisplay());

        /** @var ListThreatDecisionsCommand $listCommand */
        $listCommand = self::getContainer()->get(ListThreatDecisionsCommand::class);
        $listTester = new CommandTester($listCommand);
        $listTester->execute([]);

        self::assertStringContainsString('1.2.3.4', $listTester->getDisplay());
    }

    public function testTheCheckerMatchesADecisionSyncedIntoTheCache(): void
    {
        self::bootKernel(['environment' => 'threat_cache']);

        /** @var StaticThreatProvider $provider */
        $provider = self::getContainer()->get(StaticThreatProvider::class);
        $provider->nextBatch = new ThreatSyncBatch(added: [
            new ThreatDecision('static', '1', ThreatScope::ip(), '1.2.3.4', 'ban', new \DateTimeImmutable()),
        ]);

        /** @var SyncThreatDecisionsCommand $syncCommand */
        $syncCommand = self::getContainer()->get(SyncThreatDecisionsCommand::class);
        (new CommandTester($syncCommand))->execute([]);

        /** @var ThreatCheckerHolder $holder */
        $holder = self::getContainer()->get(ThreatCheckerHolder::class);
        $highest = $holder->checker->highestFor(new ThreatSubject(ip: '1.2.3.4'));

        self::assertNotNull($highest);
        self::assertSame('ban', $highest->type);

        // ThreatChecker::decisionsFor() memoizes per subject for the
        // lifetime of the request — kernel.reset must clear it, the same
        // way HttpActivitySubscriber/RequestContextProcessor already do.
        self::assertInstanceOf(ResetInterface::class, $holder->checker);
    }
}
