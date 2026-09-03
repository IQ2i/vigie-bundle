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

use IQ2i\VigieBundle\Model\ThreatDecision;

/**
 * What a ThreatProviderInterface::pull() call returned.
 */
final readonly class ThreatSyncBatch
{
    /**
     * @param list<ThreatDecision> $added
     * @param list<ThreatDecision> $removed only ThreatDecision::key() is guaranteed meaningful — a
     *                                      provider's own "removed" entries don't always carry a
     *                                      remaining duration to compute expiresAt from
     * @param int                  $skipped decisions the provider could not map (an unsupported scope,
     *                                      an unparsable duration) — reported, never fatal
     */
    public function __construct(
        public array $added = [],
        public array $removed = [],
        public int $skipped = 0,
    ) {
    }
}
