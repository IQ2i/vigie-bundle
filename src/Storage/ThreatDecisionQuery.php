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

use IQ2i\VigieBundle\Model\ThreatScope;

/**
 * Criteria used to filter threat decisions through ThreatDecisionStoreInterface::find()/count().
 */
final readonly class ThreatDecisionQuery
{
    /**
     * @param list<ThreatScope>   $scopes   an empty list means every scope
     * @param ?string             $value    exact match on the decision's value — mutually exclusive
     *                                      with $matchIp in practice (a caller sets one or the other),
     *                                      though nothing enforces it
     * @param ?string             $matchIp  finds every Ip/Range decision whose boundaries contain this
     *                                      address (an "Ip" decision is a degenerate range, see IpRange)
     * @param ?\DateTimeImmutable $activeAt only decisions active at this instant (expiresAt is null or
     *                                      strictly after it); null also returns expired ones
     * @param int                 $limit    hard cap — a Range scan is unbounded by nature
     */
    public function __construct(
        public array $scopes = [],
        public ?string $value = null,
        public ?string $matchIp = null,
        public ?string $provider = null,
        public ?\DateTimeImmutable $activeAt = null,
        public int $limit = 1000,
    ) {
    }
}
