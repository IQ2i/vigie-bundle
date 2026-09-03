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

namespace IQ2i\VigieBundle\Event;

use IQ2i\VigieBundle\Model\ThreatDecision;

/**
 * Dispatched by ThreatSynchronizer once a vigie:threat:sync run has already
 * applied its batch to the store — never at the moment a request matches a
 * decision (see doc/threat.md).
 *
 * $added/$removed are never pseudonymized: they carry the decision exactly
 * as the SIEM reported it, unlike what Vigie itself records under `record.*`.
 */
final readonly class ThreatDecisionsSynced
{
    /**
     * @param list<ThreatDecision> $added
     * @param list<ThreatDecision> $removed
     */
    public function __construct(
        public string $provider,
        public array $added,
        public array $removed,
        public bool $startup,
        public \DateTimeImmutable $syncedAt,
    ) {
    }
}
