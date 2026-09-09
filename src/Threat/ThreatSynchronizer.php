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
 * happened.
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
            throw new \LogicException('iq2i_vigie.threat.provider: no provider is configured, there is nothing to pull.');
        }

        $providerName = $this->provider->getName();

        $startup = $forceStartup || null === $this->store->lastSyncedAt($providerName);

        // Pulled before the store is cleared, so a provider that is down during a startup run leaves the
        // previous decisions in place instead of wiping them.
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
            // On startup, clear() already dropped the rows a "removed" entry would target.
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

        $purged = $purge ? $this->store->purgeExpired($now) : 0;

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
