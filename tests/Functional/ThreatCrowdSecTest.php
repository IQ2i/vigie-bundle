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

use IQ2i\VigieBundle\Command\SyncThreatDecisionsCommand;
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;
use IQ2i\VigieBundle\Threat\CrowdSec\CrowdSecProvider;
use IQ2i\VigieBundle\Threat\ThreatProviderInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class ThreatCrowdSecTest extends FunctionalTestCase
{
    public function testTheCrowdSecProviderIsWiredAsTheThreatProvider(): void
    {
        self::bootKernel(['environment' => 'threat_crowdsec']);

        self::assertInstanceOf(CrowdSecProvider::class, self::getContainer()->get(ThreatProviderInterface::class));
    }

    public function testSyncPullsFromTheMockedLapiAndWritesTheDecision(): void
    {
        self::bootKernel(['environment' => 'threat_crowdsec']);

        /** @var SyncThreatDecisionsCommand $syncCommand */
        $syncCommand = self::getContainer()->get(SyncThreatDecisionsCommand::class);
        $status = (new CommandTester($syncCommand))->execute([]);

        self::assertSame(Command::SUCCESS, $status);

        /** @var InMemoryThreatDecisionStore $store */
        $store = self::getContainer()->get(ThreatDecisionStoreInterface::class);
        $found = $store->find(new ThreatDecisionQuery());

        self::assertCount(1, $found);
        self::assertSame('1.2.3.4', $found[0]->value);
    }
}
