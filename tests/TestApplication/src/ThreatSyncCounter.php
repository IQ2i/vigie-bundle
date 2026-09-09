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

use IQ2i\VigieBundle\Event\ThreatDecisionsSynced;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
final class ThreatSyncCounter
{
    public int $calls = 0;

    public function __invoke(ThreatDecisionsSynced $event): void
    {
        ++$this->calls;
    }
}
