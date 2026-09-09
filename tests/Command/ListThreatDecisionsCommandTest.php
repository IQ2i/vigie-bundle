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

use IQ2i\VigieBundle\Command\ListThreatDecisionsCommand;
use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class ListThreatDecisionsCommandTest extends TestCase
{
    private function store(): InMemoryThreatDecisionStore
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::ip(), '1.2.3.4', 'ban', new \DateTimeImmutable('2026-08-21 09:00:00'), origin: 'crowdsec', scenario: 'crowdsecurity/ssh-bf'),
            new ThreatDecision('crowdsec', '2', ThreatScope::country(), 'FR', 'captcha', new \DateTimeImmutable('2026-08-21 09:00:00'), new \DateTimeImmutable('2026-08-21 08:00:00')),
        ], [], new \DateTimeImmutable('2026-08-21 09:00:00'));

        return $store;
    }

    public function testItReportsFailureWhenNoStoreIsConfigured(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand(null));

        $status = $tester->execute([]);

        self::assertSame(Command::FAILURE, $status);
        self::assertStringContainsString('No threat decision store', $tester->getDisplay());
    }

    public function testTheDefaultTableFormatListsEveryDecision(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store()));

        $status = $tester->execute([]);

        self::assertSame(Command::SUCCESS, $status);
        self::assertStringContainsString('1.2.3.4', $tester->getDisplay());
        self::assertStringContainsString('FR', $tester->getDisplay());
        self::assertStringContainsString('2 decisions shown out of 2', $tester->getDisplay());
    }

    public function testFilteringByScope(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store()));

        $tester->execute(['--scope' => ['Country']]);

        self::assertStringContainsString('FR', $tester->getDisplay());
        self::assertStringNotContainsString('1.2.3.4', $tester->getDisplay());
    }

    public function testFilteringByValue(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store()));

        $tester->execute(['--value' => '1.2.3.4']);

        self::assertStringContainsString('1.2.3.4', $tester->getDisplay());
        self::assertStringNotContainsString('FR', $tester->getDisplay());
    }

    public function testAValueIsNormalizedForTheSingleScopeItIsLookedUpIn(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store()));

        $tester->execute(['--scope' => ['country'], '--value' => 'fr']);

        self::assertStringContainsString('FR', $tester->getDisplay());
        self::assertStringContainsString('1 decision shown', $tester->getDisplay());
    }

    public function testActiveOnlyExcludesExpiredDecisions(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store(), new MockClock('2026-08-21 10:00:00')));

        $tester->execute(['--active-only' => true]);

        self::assertStringContainsString('1.2.3.4', $tester->getDisplay());
        self::assertStringNotContainsString('FR', $tester->getDisplay());
    }

    public function testJsonFormatIncludesTheScopeAndValue(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store()));

        $tester->execute(['--format' => 'json']);

        self::assertStringContainsString('"1.2.3.4"', $tester->getDisplay());
        self::assertStringContainsString('"crowdsecurity/ssh-bf"', $tester->getDisplay());
    }

    public function testCsvFormatIncludesTheHeaderRow(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store()));

        $tester->execute(['--format' => 'csv']);

        self::assertStringContainsString('provider,external_id,scope,value,type', $tester->getDisplay());
    }

    public function testAnUnknownFormatIsInvalid(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store()));

        $status = $tester->execute(['--format' => 'xml']);

        self::assertSame(Command::INVALID, $status);
    }

    public function testAnEmptyLimitIsInvalid(): void
    {
        $tester = new CommandTester(new ListThreatDecisionsCommand($this->store()));

        $status = $tester->execute(['--limit' => '0']);

        self::assertSame(Command::INVALID, $status);
    }
}
