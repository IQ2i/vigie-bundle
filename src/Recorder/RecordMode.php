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

use Symfony\Component\HttpFoundation\IpUtils;

/**
 * How ActivityRedactor treats one field of an Activity, resolved from
 * `record.*`. `ip_address: anonymize` masks the host part instead of
 * dropping the IP; `user_identifier: hash` HMACs it instead of dropping it.
 */
enum RecordMode: string
{
    case Keep = 'keep';
    case Drop = 'drop';
    case Anonymize = 'anonymize';
    case Hash = 'hash';

    public function applyToIpAddress(string $value, Pseudonymizer $pseudonymizer): ?string
    {
        return match ($this) {
            self::Drop => null,
            self::Anonymize => IpUtils::anonymize($value),
            self::Hash => $pseudonymizer->hash($value),
            self::Keep => $value,
        };
    }

    public function applyToUserIdentifier(string $value, Pseudonymizer $pseudonymizer): ?string
    {
        return match ($this) {
            self::Drop => null,
            self::Hash => $pseudonymizer->hash($value),
            self::Keep, self::Anonymize => $value,
        };
    }
}
