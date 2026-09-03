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

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Monolog\EcsDocument;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\ClockInterface;

/**
 * Logs an activity as one `info` record on a dedicated Monolog logger
 * (channel `vigie.activity`, distinct from the bundle's own `vigie`
 * diagnostics channel) — the ECS document is carried as the record's
 * context, ready for EcsFormatter or any third-party formatter to encode.
 *
 * @internal select it with `iq2i_vigie.storage: monolog` (the default, see
 * doc/storage.md) rather than instantiating it directly.
 */
final readonly class MonologActivityStorage implements ActivityStorageInterface
{
    public function __construct(
        private LoggerInterface $logger,
        private ClockInterface $clock = new Clock(),
        private ?string $app = null,
        private ?string $env = null,
    ) {
    }

    public function store(Activity $activity): void
    {
        $this->logger->info(
            EcsDocument::message($activity),
            EcsDocument::fromActivity($activity, $this->clock->now(), $this->app, $this->env),
        );
    }
}
