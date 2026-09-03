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
 * Where the decisions a ThreatSynchronizer pulls from a ThreatProviderInterface
 * are kept, read back by ThreatChecker and vigie:threat:list.
 */
interface ThreatDecisionStoreInterface
{
    /**
     * Applies one sync batch atomically: removes $removed (matched by
     * ThreatDecision::key()), upserts $added, and records $syncedAt as the
     * provider's last successful sync. Idempotent: applying the same batch
     * twice must not create a duplicate.
     *
     * @param list<ThreatDecision> $added
     * @param list<ThreatDecision> $removed only ThreatDecision::key() is read — removing a key that
     *                                      isn't currently stored is a no-op, not an error
     */
    public function apply(string $provider, array $added, array $removed, \DateTimeImmutable $syncedAt): void;

    /**
     * Drops every decision of $provider and its last sync time — the
     * "startup" resync path.
     */
    public function clear(string $provider): void;

    public function lastSyncedAt(string $provider): ?\DateTimeImmutable;

    /**
     * @return list<ThreatDecision>
     */
    public function find(ThreatDecisionQuery $query): array;

    public function count(ThreatDecisionQuery $query): int;

    /**
     * Deletes decisions whose expiresAt is at or before $now, in batches of
     * at most $batchSize, and returns the total number deleted.
     */
    public function purgeExpired(\DateTimeImmutable $now, int $batchSize): int;
}
