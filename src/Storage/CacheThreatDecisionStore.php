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
use Psr\Cache\CacheItemPoolInterface;

/**
 * ThreatDecisionStoreInterface backed by any PSR-6 pool the host application
 * already has: `cache.app`, a Redis pool, or `cache.adapter.filesystem`. A
 * provider's decisions and its last sync time live in a single cache item.
 *
 * No pre-computed IP range index: find()/count() load a provider's whole
 * decision set and filter it in PHP — fine up to a few thousand decisions.
 *
 * @internal select it with `iq2i_vigie.threat.storage: cache` rather than instantiating it directly.
 */
final class CacheThreatDecisionStore implements ThreatDecisionStoreInterface
{
    use ThreatDecisionMatching;

    private const PROVIDERS_INDEX_KEY = 'vigie_threat.providers';

    public function __construct(
        private readonly CacheItemPoolInterface $pool,
    ) {
    }

    public function apply(string $provider, array $added, array $removed, \DateTimeImmutable $syncedAt): void
    {
        $bucket = $this->loadBucket($provider);

        foreach ($removed as $decision) {
            unset($bucket['decisions'][$decision->key()]);
        }

        foreach ($added as $decision) {
            $bucket['decisions'][$decision->key()] = $decision;
        }

        $bucket['syncedAt'] = $syncedAt;

        $this->saveBucket($provider, $bucket);
        $this->trackProvider($provider);
    }

    public function clear(string $provider): void
    {
        $this->pool->deleteItem(self::itemKey($provider));
    }

    public function lastSyncedAt(string $provider): ?\DateTimeImmutable
    {
        return $this->loadBucket($provider)['syncedAt'];
    }

    public function find(ThreatDecisionQuery $query): array
    {
        $matching = [];

        foreach ($this->decisionsToScan($query) as $decision) {
            if (self::matches($decision, $query)) {
                $matching[] = $decision;

                if (\count($matching) >= $query->limit) {
                    break;
                }
            }
        }

        return $matching;
    }

    public function count(ThreatDecisionQuery $query): int
    {
        $count = 0;

        foreach ($this->decisionsToScan($query) as $decision) {
            if (self::matches($decision, $query)) {
                ++$count;
            }
        }

        return $count;
    }

    public function purgeExpired(\DateTimeImmutable $now, int $batchSize): int
    {
        // $batchSize only bounds how many rows a real storage deletes per round-trip — a cache item is rewritten whole regardless.
        $deleted = 0;

        foreach ($this->knownProviders() as $provider) {
            $bucket = $this->loadBucket($provider);
            $before = \count($bucket['decisions']);

            $bucket['decisions'] = array_filter(
                $bucket['decisions'],
                static fn (ThreatDecision $decision): bool => null === $decision->expiresAt || $decision->expiresAt > $now,
            );

            $deleted += $before - \count($bucket['decisions']);

            if ($before !== \count($bucket['decisions'])) {
                $this->saveBucket($provider, $bucket);
            }
        }

        return $deleted;
    }

    /**
     * @return iterable<ThreatDecision>
     */
    private function decisionsToScan(ThreatDecisionQuery $query): iterable
    {
        $providers = null !== $query->provider ? [$query->provider] : $this->knownProviders();

        foreach ($providers as $provider) {
            yield from $this->loadBucket($provider)['decisions'];
        }
    }

    /**
     * @return array{decisions: array<string, ThreatDecision>, syncedAt: ?\DateTimeImmutable}
     */
    private function loadBucket(string $provider): array
    {
        $item = $this->pool->getItem(self::itemKey($provider));

        if (!$item->isHit()) {
            return ['decisions' => [], 'syncedAt' => null];
        }

        /** @var array{decisions: array<string, ThreatDecision>, syncedAt: ?\DateTimeImmutable} $bucket */
        $bucket = $item->get();

        return $bucket;
    }

    /**
     * @param array{decisions: array<string, ThreatDecision>, syncedAt: ?\DateTimeImmutable} $bucket
     */
    private function saveBucket(string $provider, array $bucket): void
    {
        $item = $this->pool->getItem(self::itemKey($provider));
        $item->set($bucket);
        $this->pool->save($item);
    }

    private function trackProvider(string $provider): void
    {
        $providers = $this->knownProviders();

        if (\in_array($provider, $providers, true)) {
            return;
        }

        $providers[] = $provider;

        $item = $this->pool->getItem(self::PROVIDERS_INDEX_KEY);
        $item->set($providers);
        $this->pool->save($item);
    }

    /**
     * @return list<string>
     */
    private function knownProviders(): array
    {
        $item = $this->pool->getItem(self::PROVIDERS_INDEX_KEY);

        if (!$item->isHit()) {
            return [];
        }

        /** @var list<string> $providers */
        $providers = $item->get();

        return $providers;
    }

    /**
     * PSR-6 forbids "{}()/\@:" in a key — replacing everything outside a
     * conservative safelist keeps an arbitrary provider name usable as one.
     */
    private static function itemKey(string $provider): string
    {
        return 'vigie_threat.decisions.'.preg_replace('/[^A-Za-z0-9_.]/', '_', $provider);
    }
}
