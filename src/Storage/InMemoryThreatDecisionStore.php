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

namespace IQ2i\VigieBundle\Storage;

use IQ2i\VigieBundle\Model\ThreatDecision;

/**
 * ThreatDecisionStoreInterface kept in memory — a test double, the same way
 * InMemoryActivityStorage is for activities.
 */
final class InMemoryThreatDecisionStore implements ThreatDecisionStoreInterface
{
    use ThreatDecisionMatching;

    /**
     * @var array<string, ThreatDecision> keyed by ThreatDecision::key()
     */
    private array $decisions = [];

    /**
     * @var array<string, \DateTimeImmutable> keyed by provider
     */
    private array $syncedAt = [];

    public function apply(string $provider, array $added, array $removed, \DateTimeImmutable $syncedAt): void
    {
        foreach ($removed as $decision) {
            unset($this->decisions[$decision->key()]);
        }

        foreach ($added as $decision) {
            $this->decisions[$decision->key()] = $decision;
        }

        $this->syncedAt[$provider] = $syncedAt;
    }

    public function clear(string $provider): void
    {
        foreach ($this->decisions as $key => $decision) {
            if ($provider === $decision->provider) {
                unset($this->decisions[$key]);
            }
        }

        unset($this->syncedAt[$provider]);
    }

    public function lastSyncedAt(string $provider): ?\DateTimeImmutable
    {
        return $this->syncedAt[$provider] ?? null;
    }

    public function find(ThreatDecisionQuery $query): array
    {
        $matching = array_values(array_filter($this->decisions, static fn (ThreatDecision $decision): bool => self::matches($decision, $query)));

        return \array_slice($matching, 0, $query->limit);
    }

    public function count(ThreatDecisionQuery $query): int
    {
        return \count(array_filter($this->decisions, static fn (ThreatDecision $decision): bool => self::matches($decision, $query)));
    }

    public function purgeExpired(\DateTimeImmutable $now, int $batchSize): int
    {
        // $batchSize only bounds how many rows a real storage deletes per round-trip — in memory there is none.
        $deleted = 0;

        foreach ($this->decisions as $key => $decision) {
            if (null !== $decision->expiresAt && $decision->expiresAt <= $now) {
                unset($this->decisions[$key]);
                ++$deleted;
            }
        }

        return $deleted;
    }
}
