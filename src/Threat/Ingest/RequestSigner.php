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

namespace IQ2i\VigieBundle\Threat\Ingest;

/**
 * Signs and verifies an ingest payload with HMAC-SHA256 over
 * "<timestamp>.<body>" — what IngestController expects, and what
 * doc/threat.md shows an emitter reproducing in sh. How long a timestamp
 * stays acceptable is IngestController's business (clock_skew), not this class's.
 *
 * $timestamp is signed exactly as it travels in the header: an emitter that
 * pads or formats it differently would sign one thing and send another.
 */
final class RequestSigner
{
    public const TIMESTAMP_HEADER = 'X-Vigie-Timestamp';
    public const SIGNATURE_HEADER = 'X-Vigie-Signature';

    private const ALGORITHM = 'sha256';

    public static function sign(string $secret, string $timestamp, string $body): string
    {
        return self::ALGORITHM.'='.hash_hmac(self::ALGORITHM, $timestamp.'.'.$body, $secret);
    }

    public static function verify(string $secret, string $timestamp, string $body, string $signature): bool
    {
        return hash_equals(self::sign($secret, $timestamp, $body), $signature);
    }
}
