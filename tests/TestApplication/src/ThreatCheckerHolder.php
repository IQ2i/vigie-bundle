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
 * A thin, public consumer of ThreatCheckerInterface — this test app has no
 * controller or listener of its own that injects it, so without a real
 * consumer the compiler would prune the (otherwise private) service as
 * unused before a functional test ever gets a chance to fetch it.
 */
final class ThreatCheckerHolder
{
    public function __construct(
        public readonly ThreatCheckerInterface $checker,
    ) {
    }
}
