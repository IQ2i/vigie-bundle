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

use IQ2i\VigieBundle\Event\ThreatDecisionsSynced;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\ClockInterface;

/**
 * Orchestrates one threat sync: pull the configured provider, apply the
 * resulting batch, purge locally expired decisions, and report what
 * happened — vigie:threat:sync is a thin adapter around sync(), and the
 * threat ingest endpoint a thin adapter around applyBatch() (see
 * doc/threat.md).
 *
 * ThreatDecisionsSynced is dispatched once apply()/purgeExpired() have both
 * returned, never from inside apply(): a listener that flushes its own
 * EntityManager must not run inside whatever ThreatDecisionStoreInterface::apply()
 * still has open.
 */
final readonly class ThreatSynchronizer
{
    public function __construct(
        private ?ThreatProviderInterface $provider,
        private ThreatDecisionStoreInterface $store,
        private ?EventDispatcherInterface $dispatcher = null,
        private ClockInterface $clock = new Clock(),
        private ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * @return array{provider: string, startup: bool, added: int, removed: int, skipped: int, purged: int}
     *
     * @throws ThreatProviderException
     */
    public function sync(bool $forceStartup = false, bool $purge = true): array
    {
        if (null === $this->provider) {
            throw new \LogicException('iq2i_vigie.threat.provider: no provider is configured, there is nothing to pull — decisions can still be pushed in (see doc/threat.md).');
        }

        $providerName = $this->provider->getName();

        // A full resync is also needed when nothing has ever been synced for
        // this provider — including a local store that was wiped, restored,
        // or evicted: apply() always writes the sync time alongside the
        // decisions it just applied, so an empty store never has one left
        // over to read here either.
        $startup = $forceStartup || null === $this->store->lastSyncedAt($providerName);

        // Pulled before the store is touched: a provider that is down during
        // a startup run must leave the previous decisions in place rather
        // than wipe them and leave every request unprotected until it is
        // back.
        $batch = $this->provider->pull($startup);

        return $this->applyBatch($providerName, $batch, $startup, $purge);
    }

    /**
     * @return array{provider: string, startup: bool, added: int, removed: int, skipped: int, purged: int}
     */
    public function applyBatch(string $provider, ThreatSyncBatch $batch, bool $startup, bool $purge = true): array
    {
        $now = $this->clock->now();

        if ($startup) {
            $this->store->clear($provider);
        }

        try {
            // A startup batch's "removed" entries (every decision the
            // sender knows to have expired) all target rows clear() just
            // dropped — nothing to delete.
            $this->store->apply($provider, $batch->added, $startup ? [] : $batch->removed, $now);
        } catch (\Throwable $e) {
            if (!$startup) {
                $this->logger?->error('Vigie could not apply a delta threat batch for "{provider}"; these decisions will not be sent again, only a full startup batch recovers them: {message}', [
                    'provider' => $provider,
                    'message' => $e->getMessage(),
                    'exception' => $e,
                ]);
            }

            throw $e;
        }

        $purged = $purge ? $this->store->purgeExpired($now, 1000) : 0;

        $this->dispatch(new ThreatDecisionsSynced($provider, $batch->added, $batch->removed, $startup, $now));

        return [
            'provider' => $provider,
            'startup' => $startup,
            'added' => \count($batch->added),
            'removed' => \count($batch->removed),
            'skipped' => $batch->skipped,
            'purged' => $purged,
        ];
    }

    private function dispatch(ThreatDecisionsSynced $event): void
    {
        try {
            $this->dispatcher?->dispatch($event);
        } catch (\Throwable $e) {
            $this->logger?->warning('A ThreatDecisionsSynced listener failed after a threat sync: {message}', [
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);
        }
    }
}
