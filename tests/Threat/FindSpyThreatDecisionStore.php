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
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;

/**
 * A ThreatDecisionStoreInterface whose find() delegates to a closure and
 * counts its calls — for ThreatCheckerTest, which only exercises find().
 */
final class FindSpyThreatDecisionStore implements ThreatDecisionStoreInterface
{
    public int $calls = 0;

    /**
     * @param \Closure(): list<ThreatDecision> $find
     */
    public function __construct(
        private readonly \Closure $find,
    ) {
    }

    public function apply(string $provider, array $added, array $removed, \DateTimeImmutable $syncedAt): void
    {
    }

    public function clear(string $provider): void
    {
    }

    public function lastSyncedAt(string $provider): ?\DateTimeImmutable
    {
        return null;
    }

    public function find(ThreatDecisionQuery $query): array
    {
        ++$this->calls;

        return ($this->find)();
    }

    public function count(ThreatDecisionQuery $query): int
    {
        return 0;
    }

    public function purgeExpired(\DateTimeImmutable $now, int $batchSize): int
    {
        return 0;
    }
}
