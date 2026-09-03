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

namespace IQ2i\VigieBundle\Threat;

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Recorder\QueryNormalizer;
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Contracts\Service\ResetInterface;

/**
 * @internal select it through ThreatCheckerInterface rather than
 * instantiating or extending it
 */
final class ThreatChecker implements ThreatCheckerInterface, ResetInterface
{
    // Conventional scope names for a user identifier and a session — not CrowdSec constants, just the spelling their own documentation uses.
    private const USER_SCOPE = 'username';
    private const SESSION_SCOPE = 'session';

    /**
     * @var array<string, list<ThreatDecision>>
     */
    private array $cache = [];

    public function __construct(
        private readonly ThreatDecisionStoreInterface $store,
        private readonly ?QueryNormalizer $normalizer = null,
        private readonly bool $normalizeSubject = true,
        private readonly int $maxRanges = 5000,
        private readonly ClockInterface $clock = new Clock(),
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function decisionsFor(ThreatSubject $subject): array
    {
        $key = self::cacheKey($subject);

        if (\array_key_exists($key, $this->cache)) {
            return $this->cache[$key];
        }

        try {
            $decisions = $this->lookup($subject);
        } catch (\Throwable $e) {
            // Fail-open: an unreachable store must never turn a successful request into a 500 or a block.
            $this->logger?->error('Vigie could not check threat decisions for a subject: {message}', [
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);

            $decisions = [];
        }

        return $this->cache[$key] = $decisions;
    }

    public function highestFor(ThreatSubject $subject): ?ThreatDecision
    {
        return $this->decisionsFor($subject)[0] ?? null;
    }

    /**
     * Safety net for a worker runtime, where this service and its cache would otherwise survive across requests for different visitors.
     */
    public function reset(): void
    {
        $this->cache = [];
    }

    /**
     * @return list<ThreatDecision>
     */
    private function lookup(ThreatSubject $subject): array
    {
        $now = $this->clock->now();

        /** @var array<string, ThreatDecision> $matching keyed by ThreatDecision::key(), deduped */
        $matching = [];

        if (null !== $subject->ip) {
            $this->collect($matching, new ThreatDecisionQuery(
                scopes: [ThreatScope::ip(), ThreatScope::range()],
                matchIp: $subject->ip,
                activeAt: $now,
                limit: $this->maxRanges,
            ));
        }

        if (null !== $subject->sessionId) {
            // The only field ever normalized regardless of $normalizeSubject:
            // session_id is always HMACed when Vigie records it (never a
            // "keep raw" mode — see the ActivityRedactor docblock), so a
            // decision on this scope can only ever carry the hash.
            $scope = ThreatScope::of(self::SESSION_SCOPE);
            $value = $this->normalizer?->sessionId($subject->sessionId) ?? $subject->sessionId;
            $this->collect($matching, new ThreatDecisionQuery(scopes: [$scope], value: $scope->normalizeValue($value), activeAt: $now));
        }

        if (null !== $subject->userIdentifier) {
            $scope = ThreatScope::of(self::USER_SCOPE);
            $value = $this->normalizeSubject && null !== $this->normalizer
                ? $this->normalizer->userIdentifier($subject->userIdentifier)
                : $subject->userIdentifier;
            $this->collect($matching, new ThreatDecisionQuery(scopes: [$scope], value: $scope->normalizeValue($value), activeAt: $now));
        }

        if (null !== $subject->country) {
            $scope = ThreatScope::country();
            $this->collect($matching, new ThreatDecisionQuery(scopes: [$scope], value: $scope->normalizeValue($subject->country), activeAt: $now));
        }

        if (null !== $subject->asn) {
            $scope = ThreatScope::asn();
            $this->collect($matching, new ThreatDecisionQuery(scopes: [$scope], value: $scope->normalizeValue($subject->asn), activeAt: $now));
        }

        $decisions = array_values($matching);

        usort($decisions, self::compare(...));

        return $decisions;
    }

    /**
     * @param array<string, ThreatDecision> $matching
     */
    private function collect(array &$matching, ThreatDecisionQuery $query): void
    {
        foreach ($this->store->find($query) as $decision) {
            $matching[$decision->key()] = $decision;
        }
    }

    /**
     * Highest ThreatRemediation::priorityOf() first; among equal priorities,
     * the one with the longest remaining validity — a decision that never
     * expires sorts ahead of any with a fixed expiry.
     */
    private static function compare(ThreatDecision $a, ThreatDecision $b): int
    {
        $priority = $b->priority() <=> $a->priority();

        if (0 !== $priority) {
            return $priority;
        }

        return match (true) {
            null === $a->expiresAt && null === $b->expiresAt => 0,
            null === $a->expiresAt => -1,
            null === $b->expiresAt => 1,
            default => $b->expiresAt <=> $a->expiresAt,
        };
    }

    private static function cacheKey(ThreatSubject $subject): string
    {
        // Not implode(): a user identifier is free-form and may contain whatever separator would be picked.
        return json_encode([$subject->ip, $subject->sessionId, $subject->userIdentifier, $subject->country, $subject->asn], \JSON_THROW_ON_ERROR);
    }
}
