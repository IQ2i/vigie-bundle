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

namespace IQ2i\VigieBundle\Tests\Threat\CrowdSec;

use IQ2i\VigieBundle\Threat\CrowdSec\GoDurationParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class GoDurationParserTest extends TestCase
{
    #[DataProvider('validDurations')]
    public function testParsesAValidGoDuration(string $value, float $expectedSeconds): void
    {
        self::assertEqualsWithDelta($expectedSeconds, GoDurationParser::toSeconds($value), 0.0000001);
    }

    /**
     * @return iterable<string, array{0: string, 1: float}>
     */
    public static function validDurations(): iterable
    {
        yield 'hours only' => ['4h', 4 * 3600];
        yield 'hours, minutes and seconds' => ['3h59m32s', 3 * 3600 + 59 * 60 + 32];
        yield 'minutes and seconds' => ['1m30s', 90.0];
        yield 'zero hours, minutes and seconds' => ['720h0m0s', 720 * 3600];
        yield 'zero seconds' => ['0s', 0.0];
        yield 'negative minutes' => ['-5m', -300.0];
        yield 'explicit positive sign' => ['+5m', 300.0];
        yield 'fractional hours' => ['1.5h', 5400.0];
        yield 'milliseconds' => ['300ms', 0.3];
        yield 'microseconds, ascii spelling' => ['1us', 0.000001];
        yield 'microseconds, micro sign' => ["1\u{00B5}s", 0.000001];
        yield 'microseconds, greek mu' => ["1\u{03BC}s", 0.000001];
        yield 'nanoseconds' => ['100ns', 0.0000001];
        yield 'hours and minutes' => ['2h45m', 2 * 3600 + 45 * 60];
        yield 'every unit combined' => ['1h2m3s4ms5us6ns', 3723.004005006];
        yield 'negative compound duration' => ['-2h30m', -9000.0];
    }

    #[DataProvider('invalidDurations')]
    public function testRejectsSomethingThatIsNotAGoDuration(string $value): void
    {
        self::assertNull(GoDurationParser::toSeconds($value));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function invalidDurations(): iterable
    {
        yield 'empty string' => [''];
        yield 'whitespace only' => ['   '];
        yield 'not a duration at all' => ['abc'];
        yield 'unknown unit' => ['5x'];
        yield 'unit with no amount' => ['h'];
        yield 'trailing digits with no unit' => ['4h5'];
        yield 'double sign' => ['--1s'];
        yield 'sign with nothing after it' => ['-'];
        yield 'amount with a trailing garbage character' => ['5s!'];
    }
}
