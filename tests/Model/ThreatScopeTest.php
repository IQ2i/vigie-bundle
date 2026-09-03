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

use IQ2i\VigieBundle\Model\ThreatScope;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ThreatScopeTest extends TestCase
{
    #[DataProvider('canonicalSpellings')]
    public function testACanonicalScopeIsRecognizedCaseInsensitivelyAndFoldedToItsCanonicalSpelling(string $raw, string $expectedCanonical): void
    {
        $scope = ThreatScope::of($raw);

        self::assertSame($expectedCanonical, $scope->value);
        self::assertTrue($scope->isCaseInsensitive());
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function canonicalSpellings(): iterable
    {
        yield 'Ip already canonical' => ['Ip', 'Ip'];
        yield 'ip lowercase' => ['ip', 'Ip'];
        yield 'IP uppercase' => ['IP', 'Ip'];
        yield 'Range already canonical' => ['Range', 'Range'];
        yield 'range lowercase' => ['range', 'Range'];
        yield 'Country already canonical' => ['Country', 'Country'];
        yield 'country lowercase' => ['country', 'Country'];
        yield 'AS already canonical' => ['AS', 'AS'];
        yield 'as lowercase' => ['as', 'AS'];
        yield 'As mixed case' => ['As', 'AS'];
        yield 'surrounded by whitespace' => ['  Ip  ', 'Ip'];
    }

    #[DataProvider('nonCanonicalSpellings')]
    public function testANonCanonicalScopeIsKeptVerbatim(string $raw): void
    {
        $scope = ThreatScope::of($raw);

        self::assertSame(trim($raw), $scope->value);
        self::assertFalse($scope->isCaseInsensitive());
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function nonCanonicalSpellings(): iterable
    {
        yield 'session, lowercase' => ['session'];
        yield 'Session, capitalized — a distinct scope from "session"' => ['Session'];
        yield 'username' => ['username'];
        yield 'user' => ['user'];
        yield 'an arbitrary future scope' => ['device_fingerprint'];
    }

    public function testSessionAndCapitalizedSessionAreDistinctScopes(): void
    {
        self::assertFalse(ThreatScope::of('session')->equals(ThreatScope::of('Session')));
    }

    /**
     * @return iterable<string, array{0: ThreatScope, 1: string, 2: string}>
     */
    public static function normalizations(): iterable
    {
        yield 'lowercased for a case-insensitive scope' => [ThreatScope::asn(), 'AS1234', 'as1234'];
        yield 'uppercased for Country' => [ThreatScope::country(), 'fr', 'FR'];
        yield 'kept verbatim for a non-canonical scope' => [ThreatScope::of('session'), 'AbCdEf', 'AbCdEf'];
    }

    #[DataProvider('normalizations')]
    public function testNormalizeValue(ThreatScope $scope, string $raw, string $expected): void
    {
        self::assertSame($expected, $scope->normalizeValue($raw));
    }

    public function testEqualsComparesTheNormalizedValue(): void
    {
        self::assertTrue(ThreatScope::of('ip')->equals(ThreatScope::ip()));
        self::assertFalse(ThreatScope::of('ip')->equals(ThreatScope::range()));
    }
}
