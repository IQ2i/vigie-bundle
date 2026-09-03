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

namespace IQ2i\VigieBundle\Tests\Model;

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ThreatDecisionTest extends TestCase
{
    private function syncedAt(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('2026-08-21 10:00:00');
    }

    /**
     * @return iterable<string, array{0: ThreatScope, 1: string, 2: string}>
     */
    public static function normalizedValues(): iterable
    {
        yield 'an IP is lowercased' => [ThreatScope::ip(), '1.2.3.4', '1.2.3.4'];
        yield 'a country is uppercased' => [ThreatScope::country(), 'fr', 'FR'];
        yield 'a session is kept verbatim' => [ThreatScope::of('session'), 'AbCdEf0123456789', 'AbCdEf0123456789'];
    }

    #[DataProvider('normalizedValues')]
    public function testValueIsNormalizedPerScope(ThreatScope $scope, string $raw, string $expected): void
    {
        $decision = new ThreatDecision('crowdsec', '42', $scope, $raw, 'ban', $this->syncedAt());

        self::assertSame($expected, $decision->value);
    }

    public function testTheTypeIsLowercasedAndTrimmed(): void
    {
        $decision = new ThreatDecision('crowdsec', '42', ThreatScope::ip(), '1.2.3.4', ' BAN ', $this->syncedAt());

        self::assertSame('ban', $decision->type);
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function emptyIdentityFields(): iterable
    {
        yield 'empty provider' => ['', '42', '1.2.3.4'];
        yield 'empty externalId' => ['crowdsec', '', '1.2.3.4'];
        yield 'blank value' => ['crowdsec', '42', '   '];
    }

    #[DataProvider('emptyIdentityFields')]
    public function testAnEmptyIdentityFieldIsRejected(string $provider, string $externalId, string $value): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ThreatDecision($provider, $externalId, ThreatScope::ip(), $value, 'ban', $this->syncedAt());
    }

    public function testIsActiveWhenExpiresAtIsNull(): void
    {
        $decision = new ThreatDecision('crowdsec', '42', ThreatScope::ip(), '1.2.3.4', 'ban', $this->syncedAt());

        self::assertTrue($decision->isActive(new \DateTimeImmutable('2099-01-01')));
    }

    public function testIsActiveComparesStrictlyAgainstExpiresAt(): void
    {
        $expiresAt = new \DateTimeImmutable('2026-08-21 11:00:00');
        $decision = new ThreatDecision('crowdsec', '42', ThreatScope::ip(), '1.2.3.4', 'ban', $this->syncedAt(), expiresAt: $expiresAt);

        self::assertTrue($decision->isActive(new \DateTimeImmutable('2026-08-21 10:59:59')));
        self::assertFalse($decision->isActive($expiresAt));
        self::assertFalse($decision->isActive(new \DateTimeImmutable('2026-08-21 11:00:01')));
    }

    public function testPriorityDelegatesToThreatRemediation(): void
    {
        $ban = new ThreatDecision('crowdsec', '1', ThreatScope::ip(), '1.2.3.4', 'ban', $this->syncedAt());
        $captcha = new ThreatDecision('crowdsec', '2', ThreatScope::ip(), '1.2.3.5', 'captcha', $this->syncedAt());

        self::assertGreaterThan($captcha->priority(), $ban->priority());
    }

    public function testOriginAndScenarioAreNulledWhenEmpty(): void
    {
        $decision = new ThreatDecision('crowdsec', '42', ThreatScope::ip(), '1.2.3.4', 'ban', $this->syncedAt(), origin: '', scenario: '');

        self::assertNull($decision->origin);
        self::assertNull($decision->scenario);
    }
}
