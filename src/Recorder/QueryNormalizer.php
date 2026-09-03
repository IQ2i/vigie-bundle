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

namespace IQ2i\VigieBundle\Recorder;

/**
 * Applies to a value the same transformation ActivityRedactor applies at
 * write time, so matching against it by a plain-text value still hits a
 * pseudonymized column instead of silently missing. Used by ThreatChecker
 * (threat.match.normalize_subject) to match a ThreatSubject's plain-text
 * session/user identifier against decisions keyed on the pseudonymized
 * value activities were recorded under.
 */
final readonly class QueryNormalizer
{
    public function __construct(
        private RecordingOptions $options,
        private Pseudonymizer $pseudonymizer,
    ) {
    }

    public function userIdentifier(string $value): string
    {
        return $this->options->userIdentifierMode->applyToUserIdentifier($value, $this->pseudonymizer) ?? $value;
    }

    /**
     * sessionId is always hashed when recorded — see ActivityRedactor.
     */
    public function sessionId(string $value): string
    {
        return $this->pseudonymizer->hash($value);
    }
}
