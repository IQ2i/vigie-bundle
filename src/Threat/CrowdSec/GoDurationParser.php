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

namespace IQ2i\VigieBundle\Threat\CrowdSec;

/**
 * Parses a Go duration string ("4h", "3h59m32s", "-2h30m", "300ms", "0s") —
 * the format the CrowdSec LAPI reports a decision's remaining duration in.
 * Accepts a negative value (an already-expired decision) and sub-second
 * units.
 *
 * @internal
 */
final class GoDurationParser
{
    private const PATTERN = '/(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/u';

    /**
     * @return ?float signed seconds
     */
    public static function toSeconds(string $value): ?float
    {
        $remaining = trim($value);

        if ('' === $remaining) {
            return null;
        }

        $sign = 1.0;

        if ('-' === $remaining[0] || '+' === $remaining[0]) {
            $sign = '-' === $remaining[0] ? -1.0 : 1.0;
            $remaining = substr($remaining, 1);
        }

        if ('' === $remaining) {
            return null;
        }

        $seconds = 0.0;
        $offset = 0;
        $length = \strlen($remaining);

        while ($offset < $length) {
            if (1 !== preg_match(self::PATTERN, $remaining, $matches, \PREG_OFFSET_CAPTURE, $offset)) {
                return null;
            }

            if ($matches[0][1] !== $offset) {
                // A gap between $offset and the next match means garbage in
                // between (e.g. "4h5" — a trailing number with no unit).
                return null;
            }

            $seconds += (float) $matches[1][0] * self::unitSeconds($matches[2][0]);
            $offset += \strlen($matches[0][0]);
        }

        return $sign * $seconds;
    }

    private static function unitSeconds(string $unit): float
    {
        return match ($unit) {
            'ns' => 1e-9,
            'us', 'µs', 'μs' => 1e-6,
            'ms' => 1e-3,
            's' => 1.0,
            'm' => 60.0,
            'h' => 3600.0,
            default => 0.0, // unreachable — self::PATTERN only captures known units
        };
    }
}
