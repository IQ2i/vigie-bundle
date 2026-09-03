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

namespace IQ2i\VigieBundle\Command;

/**
 * @internal
 */
final class CsvWriter
{
    private const FORMULA_PREFIXES = ['=', '+', '-', '@', "\t", "\r"];

    private function __construct()
    {
    }

    /**
     * Neutralizes CSV formula injection: a cell starting with =, +, -, @, a
     * tab or a carriage return is interpreted as a live formula by Excel and
     * LibreOffice when the file is opened — and every value written here can
     * come straight from attacker-controlled input (a User-Agent header, a
     * request URI, a user identifier).
     */
    private static function sanitize(bool|float|int|string|null $value): bool|float|int|string|null
    {
        if (!\is_string($value) || '' === $value) {
            return $value;
        }

        foreach (self::FORMULA_PREFIXES as $prefix) {
            if (str_starts_with($value, $prefix)) {
                return "'".$value;
            }
        }

        return $value;
    }

    /**
     * @param resource                                      $stream
     * @param array<int|string, bool|float|int|string|null> $fields
     */
    public static function writeRow($stream, array $fields): void
    {
        fputcsv($stream, array_map(self::sanitize(...), $fields), escape: '\\');
    }
}
