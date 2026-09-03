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
use IQ2i\VigieBundle\Threat\ThreatSubject;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched by ThreatEnforcementSubscriber when the current request matches
 * at least one active threat decision, before threat.enforce.remediations is
 * applied: setResponse() replaces whatever that table would have done.
 *
 * Dispatched even when the table holds no entry for $decision->type —
 * observing without blocking is what an empty table is for (see
 * doc/threat.md).
 */
final class ThreatDecisionMatched extends Event
{
    private ?Response $response = null;

    /**
     * @param ThreatDecision       $decision  the highest-priority match, the one the table is applied to
     * @param list<ThreatDecision> $decisions every active decision matching $subject, highest first
     */
    public function __construct(
        public readonly Request $request,
        public readonly ThreatSubject $subject,
        public readonly ThreatDecision $decision,
        public readonly array $decisions,
    ) {
    }

    public function getResponse(): ?Response
    {
        return $this->response;
    }

    public function setResponse(Response $response): void
    {
        $this->response = $response;
    }
}
