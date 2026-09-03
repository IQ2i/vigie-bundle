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

use IQ2i\VigieBundle\Threat\ThreatProviderException;
use IQ2i\VigieBundle\Threat\ThreatProviderInterface;
use IQ2i\VigieBundle\Threat\ThreatSyncBatch;

final class FakeThreatProvider implements ThreatProviderInterface
{
    /**
     * @var list<bool>
     */
    public array $calls = [];

    public ThreatSyncBatch $nextBatch;

    public ?ThreatProviderException $throws = null;

    public function __construct(
        private readonly string $name = 'fake',
    ) {
        $this->nextBatch = new ThreatSyncBatch();
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function pull(bool $startup): ThreatSyncBatch
    {
        $this->calls[] = $startup;

        if (null !== $this->throws) {
            throw $this->throws;
        }

        return $this->nextBatch;
    }
}
