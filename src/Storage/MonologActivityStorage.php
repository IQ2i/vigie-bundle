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
 * Logs an activity as one `info` record on a dedicated Monolog logger,
 * with the ECS document carried as the record's context.
 *
 * @internal
 */
final readonly class MonologActivityStorage implements ActivityStorageInterface
{
    private ?string $hostname;

    /**
     * @param bool|string $hostname true resolves gethostname() here, at runtime; false omits
     *                              "host.hostname" entirely; a string sets it explicitly
     */
    public function __construct(
        private LoggerInterface $logger,
        private ClockInterface $clock = new Clock(),
        private ?string $app = null,
        private ?string $env = null,
        bool|string $hostname = false,
    ) {
        $this->hostname = match (true) {
            true === $hostname => gethostname() ?: null,
            false === $hostname => null,
            default => '' !== trim($hostname) ? $hostname : null,
        };
    }

    public function store(Activity $activity): void
    {
        $this->logger->info(
            EcsDocument::message($activity),
            EcsDocument::fromActivity($activity, $this->clock->now(), $this->app, $this->env, $this->hostname),
        );
    }
}
