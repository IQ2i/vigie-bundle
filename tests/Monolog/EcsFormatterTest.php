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

namespace IQ2i\VigieBundle\Tests\Monolog;

use IQ2i\VigieBundle\Monolog\EcsFormatter;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;

final class EcsFormatterTest extends TestCase
{
    public function testFormatProducesOneNewlineTerminatedJsonLine(): void
    {
        $record = $this->record(context: ['vigie' => ['type' => 'custom']]);

        $line = (new EcsFormatter())->format($record);

        self::assertStringEndsWith("\n", $line);
        self::assertSame(1, substr_count($line, "\n"));
        self::assertJson(rtrim($line, "\n"));
    }

    public function testARecordsOwnAtTimestampWinsOverTheLogRecordDatetime(): void
    {
        // EcsDocument::fromActivity() sets "@timestamp" to occurredAt, not
        // to the moment the line is written — the formatter must not
        // overwrite it with $record->datetime.
        $record = $this->record(context: ['@timestamp' => '2020-01-01T00:00:00.000000+00:00']);

        $data = $this->decode((new EcsFormatter())->format($record));

        self::assertSame('2020-01-01T00:00:00.000000+00:00', $data['@timestamp']);
    }

    public function testAForeignRecordWithNoContextTimestampFallsBackToTheLogRecordDatetime(): void
    {
        $record = $this->record(datetime: new \DateTimeImmutable('2026-08-21 10:00:00', new \DateTimeZone('UTC')));

        $data = $this->decode((new EcsFormatter())->format($record));

        /** @var string $timestamp */
        $timestamp = $data['@timestamp'];
        self::assertStringStartsWith('2026-08-21T10:00:00', $timestamp);
    }

    public function testTheLogRecordMessageIsUsedWhenContextHasNoneOfItsOwn(): void
    {
        $record = $this->record(message: 'login_failure jane.doe');

        $data = $this->decode((new EcsFormatter())->format($record));

        self::assertSame('login_failure jane.doe', $data['message']);
    }

    public function testContextIsMergedIntoTheTopLevelDocument(): void
    {
        $record = $this->record(context: ['event' => ['kind' => 'event'], 'vigie' => ['type' => 'custom']]);

        $data = $this->decode((new EcsFormatter())->format($record));

        self::assertSame(['kind' => 'event'], $data['event']);
        self::assertSame(['type' => 'custom'], $data['vigie']);
    }

    public function testFormatBatchFormatsEveryRecord(): void
    {
        $formatter = new EcsFormatter();
        $records = [$this->record(message: 'one'), $this->record(message: 'two')];

        $lines = $formatter->formatBatch($records);

        self::assertCount(2, $lines);
        self::assertSame('one', $this->decode($lines[0])['message']);
        self::assertSame('two', $this->decode($lines[1])['message']);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function record(array $context = [], string $message = 'test', ?\DateTimeImmutable $datetime = null): LogRecord
    {
        return new LogRecord(
            datetime: $datetime ?? new \DateTimeImmutable(),
            channel: 'vigie.activity',
            level: Level::Info,
            message: $message,
            context: $context,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $line): array
    {
        /** @var array<string, mixed> $data */
        $data = json_decode($line, true, flags: \JSON_THROW_ON_ERROR);

        return $data;
    }
}
