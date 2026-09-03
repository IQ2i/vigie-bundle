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

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Recorder\Pseudonymizer;
use IQ2i\VigieBundle\Recorder\QueryNormalizer;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use IQ2i\VigieBundle\Tests\TestApplication\CollectingLogger;
use IQ2i\VigieBundle\Threat\ThreatChecker;
use IQ2i\VigieBundle\Threat\ThreatSubject;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class ThreatCheckerTest extends TestCase
{
    private function decision(string $externalId, ThreatScope $scope, string $value, string $type = 'ban', ?\DateTimeImmutable $expiresAt = null): ThreatDecision
    {
        return new ThreatDecision('crowdsec', $externalId, $scope, $value, $type, new \DateTimeImmutable('2026-08-21 09:00:00'), $expiresAt);
    }

    /**
     * @param bool|'hash' $userIdentifier
     */
    private function normalizer(bool|string $userIdentifier = true): QueryNormalizer
    {
        return new QueryNormalizer(new RecordingOptions(userIdentifier: $userIdentifier), new Pseudonymizer('secret'));
    }

    /**
     * @return iterable<string, array{0: ThreatScope, 1: string, 2: ThreatSubject}>
     */
    public static function matchingDecisions(): iterable
    {
        yield 'an exact IP' => [ThreatScope::ip(), '1.2.3.4', new ThreatSubject(ip: '1.2.3.4')];
        yield 'a country, case insensitively' => [ThreatScope::country(), 'FR', new ThreatSubject(country: 'fr')];
        yield 'an AS number' => [ThreatScope::asn(), 'AS1234', new ThreatSubject(asn: 'AS1234')];
        yield 'a user identifier kept in the clear' => [ThreatScope::of('username'), 'jane.doe', new ThreatSubject(userIdentifier: 'jane.doe')];
    }

    #[DataProvider('matchingDecisions')]
    public function testASubjectMatchingAStoredDecision(ThreatScope $scope, string $value, ThreatSubject $subject): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [$this->decision('1', $scope, $value)], [], new \DateTimeImmutable());
        $checker = new ThreatChecker($store, clock: new MockClock('2026-08-21 10:00:00'));

        self::assertCount(1, $checker->decisionsFor($subject));
    }

    public function testAnIpInsideACidrRangeMatches(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::range(), '1.2.3.0/24')], [], new \DateTimeImmutable());
        $checker = new ThreatChecker($store, clock: new MockClock('2026-08-21 10:00:00'));

        self::assertCount(1, $checker->decisionsFor(new ThreatSubject(ip: '1.2.3.42')));
        self::assertCount(0, $checker->decisionsFor(new ThreatSubject(ip: '1.2.4.1')));
    }

    public function testAnExpiredDecisionIsIgnoredEvenIfTheStoreStillHoldsIt(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::ip(), '1.2.3.4', expiresAt: new \DateTimeImmutable('2026-08-21 09:30:00'))], [], new \DateTimeImmutable());
        $checker = new ThreatChecker($store, clock: new MockClock('2026-08-21 10:00:00'));

        self::assertSame([], $checker->decisionsFor(new ThreatSubject(ip: '1.2.3.4')));
    }

    public function testBanOutranksCaptcha(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            $this->decision('1', ThreatScope::ip(), '1.2.3.4', 'captcha'),
            $this->decision('2', ThreatScope::country(), 'FR', 'ban'),
        ], [], new \DateTimeImmutable());
        $checker = new ThreatChecker($store, clock: new MockClock('2026-08-21 10:00:00'));

        $highest = $checker->highestFor(new ThreatSubject(ip: '1.2.3.4', country: 'FR'));

        self::assertNotNull($highest);
        self::assertSame('ban', $highest->type);
    }

    public function testASessionValueIsNormalizedThroughTheHashSinceSessionIdIsAlwaysHmaced(): void
    {
        $normalizer = $this->normalizer();
        $store = new InMemoryThreatDecisionStore();
        $hash = $normalizer->sessionId('raw-session-id');
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::of('session'), $hash)], [], new \DateTimeImmutable());
        $checker = new ThreatChecker($store, $normalizer, clock: new MockClock('2026-08-21 10:00:00'));

        self::assertCount(1, $checker->decisionsFor(new ThreatSubject(sessionId: 'raw-session-id')));
    }

    public function testAUserIdentifierIsNormalizedWhenHashModeIsConfigured(): void
    {
        $normalizer = $this->normalizer(userIdentifier: 'hash');
        $store = new InMemoryThreatDecisionStore();
        $hash = $normalizer->userIdentifier('jane.doe');
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::of('username'), $hash)], [], new \DateTimeImmutable());
        $checker = new ThreatChecker($store, $normalizer, clock: new MockClock('2026-08-21 10:00:00'));

        self::assertCount(1, $checker->decisionsFor(new ThreatSubject(userIdentifier: 'jane.doe')));
    }

    public function testDisablingNormalizeSubjectSkipsTheHash(): void
    {
        $normalizer = $this->normalizer(userIdentifier: 'hash');
        $store = new InMemoryThreatDecisionStore();
        // A decision authored with the plain-text value, matching what a
        // raw lookup would need.
        $store->apply('crowdsec', [$this->decision('1', ThreatScope::of('username'), 'jane.doe')], [], new \DateTimeImmutable());
        $checker = new ThreatChecker($store, $normalizer, normalizeSubject: false, clock: new MockClock('2026-08-21 10:00:00'));

        self::assertCount(1, $checker->decisionsFor(new ThreatSubject(userIdentifier: 'jane.doe')));
    }

    public function testNoMatchReturnsAnEmptyArrayWithoutError(): void
    {
        $checker = new ThreatChecker(new InMemoryThreatDecisionStore(), clock: new MockClock('2026-08-21 10:00:00'));

        self::assertSame([], $checker->decisionsFor(new ThreatSubject(ip: '1.2.3.4')));
        self::assertNull($checker->highestFor(new ThreatSubject(ip: '1.2.3.4')));
    }

    public function testAStoreThatThrowsIsCaughtAndLogged(): void
    {
        $store = new FindSpyThreatDecisionStore(static function (): never {
            throw new \RuntimeException('store is down');
        });

        $logger = new CollectingLogger();
        $checker = new ThreatChecker($store, clock: new MockClock('2026-08-21 10:00:00'), logger: $logger);

        self::assertSame([], $checker->decisionsFor(new ThreatSubject(ip: '1.2.3.4')));
        self::assertNotEmpty($logger->records);
        self::assertSame('error', $logger->records[0]['level']);
    }

    public function testTheStoreIsOnlyQueriedOncePerSubjectPerRequestUntilReset(): void
    {
        $store = new FindSpyThreatDecisionStore(static fn (): array => []);
        $checker = new ThreatChecker($store, clock: new MockClock('2026-08-21 10:00:00'));
        $subject = new ThreatSubject(ip: '1.2.3.4');

        $checker->decisionsFor($subject);
        $checker->decisionsFor($subject);
        $checker->highestFor($subject);
        self::assertSame(1, $store->calls);

        $checker->reset();
        $checker->decisionsFor($subject);
        self::assertSame(2, $store->calls);
    }
}
