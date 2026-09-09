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

use IQ2i\VigieBundle\Threat\ThreatCheckerInterface;

/**
 * A public consumer of ThreatCheckerInterface, so the compiler doesn't prune the otherwise-unused service.
 */
final class ThreatCheckerHolder
{
    public function __construct(
        public readonly ThreatCheckerInterface $checker,
    ) {
    }
}
