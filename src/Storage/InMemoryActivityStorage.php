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

/**
 * Keeps every stored activity in memory, in order — meant for
 * `iq2i_vigie.storage: in_memory` in a test environment to assert "this
 * request recorded that activity" without a real destination (see
 * VigieAssertionsTrait and doc/testing.md).
 */
final class InMemoryActivityStorage implements ActivityStorageInterface
{
    /**
     * @var list<Activity>
     */
    private array $activities = [];

    public function store(Activity $activity): void
    {
        $this->activities[] = $activity;
    }

    /**
     * @return list<Activity>
     */
    public function all(): array
    {
        return $this->activities;
    }
}
