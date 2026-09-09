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
use IQ2i\VigieBundle\Tests\TestApplication\ThreatCheckerHolder;
use IQ2i\VigieBundle\Tests\TestApplication\ThreatSyncCounter;
use IQ2i\VigieBundle\Threat\Ingest\RequestSigner;
use IQ2i\VigieBundle\Threat\ThreatSubject;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class ThreatIngestTest extends FunctionalTestCase
{
    private const SECRET = 'test-secret';

    public function testASignedPushIsAppliedAndVisibleToTheChecker(): void
    {
        $client = self::createClient(['environment' => 'threat_ingest']);
        $client->disableReboot();

        $body = json_encode([
            'added' => [
                ['id' => 'wz-1', 'scope' => 'Ip', 'value' => '203.0.113.42', 'type' => 'ban'],
            ],
        ], \JSON_THROW_ON_ERROR);
        $timestamp = (string) time();

        $client->request('POST', '/vigie/threat/ingest/wazuh', content: $body, server: [
            'HTTP_'.strtoupper(str_replace('-', '_', RequestSigner::TIMESTAMP_HEADER)) => $timestamp,
            'HTTP_'.strtoupper(str_replace('-', '_', RequestSigner::SIGNATURE_HEADER)) => RequestSigner::sign(self::SECRET, $timestamp, $body),
        ]);

        self::assertSame(202, $client->getResponse()->getStatusCode());

        /** @var ThreatCheckerHolder $holder */
        $holder = self::getContainer()->get(ThreatCheckerHolder::class);
        $highest = $holder->checker->highestFor(new ThreatSubject(ip: '203.0.113.42'));

        self::assertNotNull($highest);
        self::assertSame('ban', $highest->type);

        /** @var ThreatSyncCounter $counter */
        $counter = self::getContainer()->get(ThreatSyncCounter::class);
        self::assertSame(1, $counter->calls);
    }

    public function testAnUnsignedPushIsRefusedByTheRoute(): void
    {
        $client = self::createClient(['environment' => 'threat_ingest']);
        $client->disableReboot();

        $client->request('POST', '/vigie/threat/ingest/wazuh', content: '{"added":[]}');

        self::assertSame(401, $client->getResponse()->getStatusCode());

        /** @var ThreatCheckerHolder $holder */
        $holder = self::getContainer()->get(ThreatCheckerHolder::class);
        self::assertNull($holder->checker->highestFor(new ThreatSubject(ip: '203.0.113.42')));
    }

    public function testTheSynchronizerIsWiredWithoutAnyProvider(): void
    {
        self::bootKernel(['environment' => 'threat_ingest']);

        /** @var SyncThreatDecisionsCommand $command */
        $command = self::getContainer()->get(SyncThreatDecisionsCommand::class);
        $tester = new CommandTester($command);
        $status = $tester->execute([]);

        self::assertSame(Command::FAILURE, $status);
        self::assertStringContainsString('iq2i_vigie.threat.provider', $tester->getDisplay());
    }
}
