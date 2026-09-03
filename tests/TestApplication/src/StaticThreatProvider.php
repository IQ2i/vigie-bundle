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

use IQ2i\VigieBundle\Threat\ThreatProviderInterface;
use IQ2i\VigieBundle\Threat\ThreatSyncBatch;

/**
 * A ThreatProviderInterface a functional test can configure before invoking
 * vigie:threat:sync — fetch it from the container (it's registered public)
 * and set $nextBatch.
 */
final class StaticThreatProvider implements ThreatProviderInterface
{
    public ThreatSyncBatch $nextBatch;

    public function __construct()
    {
        $this->nextBatch = new ThreatSyncBatch();
    }

    public function getName(): string
    {
        return 'static';
    }

    public function pull(bool $startup): ThreatSyncBatch
    {
        return $this->nextBatch;
    }
}
