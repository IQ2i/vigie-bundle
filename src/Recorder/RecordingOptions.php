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
 * Which fields of a recorded Activity actually get stored — the GDPR/PII
 * knobs behind `iq2i_vigie.record.*`. `$ipAddress` and `$userIdentifier`
 * accept a pseudonymization mode instead of a flat `false` — see RecordMode.
 */
final readonly class RecordingOptions
{
    public RecordMode $ipAddressMode;
    public RecordMode $userIdentifierMode;

    /**
     * @param bool|'anonymize' $ipAddress
     * @param bool|'hash'      $userIdentifier
     */
    public function __construct(
        bool|string $ipAddress = 'anonymize',
        bool|string $userIdentifier = true,
        public bool $userAgent = true,
        public bool $uri = true,
        public bool $route = true,
        public bool $method = true,
        public bool $statusCode = true,
        public bool $context = true,
        public bool $firewall = true,
        public bool $sessionId = true,
        public bool $requestId = true,
    ) {
        $this->ipAddressMode = self::mode($ipAddress, RecordMode::Anonymize);
        $this->userIdentifierMode = self::mode($userIdentifier, RecordMode::Hash);
    }

    private static function mode(bool|string $value, RecordMode $pseudonymized): RecordMode
    {
        if (true === $value) {
            return RecordMode::Keep;
        }

        if (false === $value) {
            return RecordMode::Drop;
        }

        return $pseudonymized;
    }
}
