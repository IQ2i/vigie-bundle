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

namespace IQ2i\VigieBundle\Tests\Command;

use IQ2i\VigieBundle\Command\CsvWriter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CsvWriterTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string}>
     */
    public static function formulaPrefixes(): iterable
    {
        yield 'equals' => ['=cmd|\'/c calc\'!A1'];
        yield 'plus' => ['+1+1'];
        yield 'minus' => ['-1+1'];
        yield 'at' => ['@SUM(1,1)'];
        yield 'tab' => ["\tmalicious"];
        yield 'carriage return' => ["\rmalicious"];
    }

    #[DataProvider('formulaPrefixes')]
    public function testItPrefixesFormulaLikeValuesWithAQuote(string $value): void
    {
        self::assertSame("'".$value, self::writeAndReadBack([$value]));
    }

    public function testItLeavesOrdinaryValuesUntouched(): void
    {
        self::assertSame('jane.doe', self::writeAndReadBack(['jane.doe']));
        self::assertSame('Mozilla/5.0', self::writeAndReadBack(['Mozilla/5.0']));
    }

    public function testItLeavesNonStringValuesUntouched(): void
    {
        self::assertSame(['200', '', ''], self::writeAndReadBackRow([200, null, '']));
    }

    /**
     * @param array<int|string, bool|float|int|string|null> $fields
     */
    private static function writeAndReadBack(array $fields): ?string
    {
        return self::writeAndReadBackRow($fields)[0] ?? null;
    }

    /**
     * @param array<int|string, bool|float|int|string|null> $fields
     *
     * @return list<string|null>
     */
    private static function writeAndReadBackRow(array $fields): array
    {
        $stream = fopen('php://memory', 'r+');
        \assert(false !== $stream);

        CsvWriter::writeRow($stream, $fields);
        rewind($stream);

        $row = fgetcsv($stream, escape: '\\');
        \assert(false !== $row);

        return $row;
    }
}
