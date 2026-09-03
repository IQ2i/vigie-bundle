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
 * Packs an IP address or a CIDR range into fixed-size 16-byte binary
 * boundaries, mapping an IPv4 address into the IPv4-mapped IPv6 range
 * ("::ffff:a.b.c.d") so both compare byte-for-byte the same way — in a
 * BINARY(16)/BYTEA column or an in-process sorted array — turning a
 * "is this IP inside any of these ranges?" lookup into a range scan instead
 * of testing every stored CIDR string with IpUtils::checkIp().
 *
 * @internal
 */
final class IpRange
{
    private const IPV4_MAPPED_PREFIX = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";

    private function __construct()
    {
    }

    /**
     * @return ?string 16 raw bytes
     */
    public static function pack(string $ip): ?string
    {
        if (false === filter_var($ip, \FILTER_VALIDATE_IP)) {
            return null;
        }

        $binary = inet_pton($ip);

        if (false === $binary) {
            return null; // unreachable: filter_var already validated $ip
        }

        return 4 === \strlen($binary) ? self::IPV4_MAPPED_PREFIX.$binary : $binary;
    }

    /**
     * Accepts either a bare IP (a degenerate range of exactly one address) or
     * a CIDR ("1.2.3.0/24", "2001:db8::/32").
     *
     * @return ?array{0: string, 1: string} [start, end], both 16 raw bytes, start always <= end
     *                                      byte-for-byte; null if $value is neither
     */
    public static function parse(string $value): ?array
    {
        if (!str_contains($value, '/')) {
            $packed = self::pack($value);

            return null !== $packed ? [$packed, $packed] : null;
        }

        [$address, $rawPrefix] = explode('/', $value, 2);

        $prefix = filter_var($rawPrefix, \FILTER_VALIDATE_INT);
        $packedAddress = self::pack($address);

        if (false === $prefix || null === $packedAddress) {
            return null;
        }

        // Not "contains a dot": an IPv4-mapped IPv6 address ("::ffff:1.2.3.0/120")
        // has dots too, but its prefix counts over 128 bits.
        $isIpv4 = !str_contains($address, ':');
        $maxPrefix = $isIpv4 ? 32 : 128;

        if ($prefix < 0 || $prefix > $maxPrefix) {
            return null;
        }

        // An IPv4-mapped address only varies over its last 32 bits — a
        // "/24" therefore means the top (128 - 32) + 24 = 120 bits are fixed.
        $effectivePrefix = $isIpv4 ? (128 - $maxPrefix) + $prefix : $prefix;
        $mask = self::mask($effectivePrefix);

        $start = '';
        $end = '';

        for ($i = 0; $i < 16; ++$i) {
            $addressByte = \ord($packedAddress[$i]);
            $maskByte = \ord($mask[$i]);

            $start .= \chr($addressByte & $maskByte);
            $end .= \chr($addressByte | (~$maskByte & 0xFF));
        }

        return [$start, $end];
    }

    /**
     * @return string 16 raw bytes, the top $prefixBits set to 1, the rest to 0
     */
    private static function mask(int $prefixBits): string
    {
        $fullBytes = intdiv($prefixBits, 8);
        $remainderBits = $prefixBits % 8;
        $mask = '';

        for ($i = 0; $i < 16; ++$i) {
            $mask .= match (true) {
                $i < $fullBytes => "\xff",
                $i === $fullBytes && $remainderBits > 0 => \chr((0xFF << (8 - $remainderBits)) & 0xFF),
                default => "\x00",
            };
        }

        return $mask;
    }
}
