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

namespace IQ2i\VigieBundle\Tests\TestApplication;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Storage\ActivityStorageInterface;

/**
 * An ActivityStorageInterface that always throws.
 */
final class ThrowingActivityStorage implements ActivityStorageInterface
{
    public function store(Activity $activity): void
    {
        throw new \RuntimeException('connection refused');
    }
}
