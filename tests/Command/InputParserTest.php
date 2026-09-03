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

use IQ2i\VigieBundle\Command\InputParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

final class InputParserTest extends TestCase
{
    public function testIntReturnsNullWhenTheOptionIsNotSet(): void
    {
        self::assertNull(InputParser::int($this->input([]), 'limit', 1));
    }

    /**
     * @return iterable<string, array{string, int, ?int}>
     */
    public static function validIntProvider(): iterable
    {
        yield 'at the minimum' => ['1', 1, null];
        yield 'above the minimum, no maximum' => ['50', 1, null];
        yield 'at the maximum' => ['10', 1, 10];
        yield 'strictly between min and max' => ['5', 1, 10];
        yield 'zero as a valid minimum' => ['0', 0, null];
    }

    #[DataProvider('validIntProvider')]
    public function testIntAcceptsValuesInRange(string $value, int $min, ?int $max): void
    {
        self::assertSame((int) $value, InputParser::int($this->input(['--limit' => $value]), 'limit', $min, $max));
    }

    /**
     * @return iterable<string, array{string, int, ?int}>
     */
    public static function invalidIntProvider(): iterable
    {
        yield 'below the minimum' => ['0', 1, null];
        yield 'above the maximum' => ['11', 1, 10];
        yield 'not numeric at all' => ['abc', 1, null];
        yield 'a float' => ['1.5', 1, null];
        yield 'empty string' => ['', 1, null];
    }

    #[DataProvider('invalidIntProvider')]
    public function testIntRejectsValuesOutsideRangeOrNotAnInteger(string $value, int $min, ?int $max): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Option "--limit" must be');

        InputParser::int($this->input(['--limit' => $value]), 'limit', $min, $max);
    }

    /**
     * @param array<string, string> $options
     */
    private function input(array $options): InputInterface
    {
        $definition = new InputDefinition([
            new InputOption('limit', mode: InputOption::VALUE_REQUIRED),
        ]);

        return new ArrayInput($options, $definition);
    }
}
