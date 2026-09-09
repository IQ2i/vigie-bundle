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
 * @internal
 *
 * Turns an identifying value (a user identifier, a session id) into a
 * fixed-length, non-reversible token, keyed by an application secret
 * (`%kernel.secret%` by default, overridable via `record.hash_secret`) so
 * it can't be brute-forced offline the way a bare SHA-256 could. Rotating
 * the secret invalidates every previously stored hash.
 */
final readonly class Pseudonymizer
{
    public function __construct(
        private string $secret,
    ) {
    }

    /**
     * @return non-empty-string a 64-character lowercase hex digest
     */
    public function hash(string $value): string
    {
        return hash_hmac('sha256', $value, $this->secret);
    }
}
