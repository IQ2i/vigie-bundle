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

/**
 * A single point of contact with one SIEM's decision feed, polled by
 * ThreatSynchronizer. A second SIEM only needs a new class implementing this
 * interface plus a service id to point `iq2i_vigie.threat.provider` at — see
 * doc/threat.md.
 */
interface ThreatProviderInterface
{
    /**
     * Short, stable identifier of the SIEM this provider talks to
     * ("crowdsec") — stamped on every ThreatDecision it produces.
     */
    public function getName(): string;

    /**
     * @param bool $startup requests a full resync of every currently active decision, instead of
     *                      a delta since the last successful sync
     *
     * @throws ThreatProviderException
     */
    public function pull(bool $startup): ThreatSyncBatch;
}
