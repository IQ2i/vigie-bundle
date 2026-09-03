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
 * The read side of the threat decision store: "is this visitor concerned by
 * a decision, and if so, which one matters most?" Call this from a voter, a
 * kernel.request listener of your own, or a controller — or opt into
 * ThreatEnforcementSubscriber to have it answered automatically.
 *
 * A store failure never turns a successful request into a 500: it is caught,
 * logged on the "vigie" channel, and answered as "no decision found" — fail-open.
 */
interface ThreatCheckerInterface
{
    /**
     * Every active decision matching $subject, most severe first (ban
     * before captcha — see ThreatRemediation), then soonest-to-expire last.
     *
     * @return list<ThreatDecision>
     */
    public function decisionsFor(ThreatSubject $subject): array;

    /**
     * Sugar over decisionsFor() — the single decision an application most
     * likely wants to act on, or null when none matches.
     */
    public function highestFor(ThreatSubject $subject): ?ThreatDecision;
}
