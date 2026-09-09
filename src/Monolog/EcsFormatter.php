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

namespace IQ2i\VigieBundle\Monolog;

use Monolog\Formatter\FormatterInterface;
use Monolog\LogRecord;

/**
 * Encodes a LogRecord as one line of NDJSON. A union, not an array_merge(),
 * so a context already carrying its own "@timestamp" keeps it.
 */
final readonly class EcsFormatter implements FormatterInterface
{
    private const ENCODE_FLAGS = \JSON_UNESCAPED_SLASHES
        | \JSON_UNESCAPED_UNICODE
        | \JSON_INVALID_UTF8_SUBSTITUTE
        | \JSON_PRESERVE_ZERO_FRACTION
        | \JSON_THROW_ON_ERROR;

    private const DATE_FORMAT = 'Y-m-d\TH:i:s.uP';

    /**
     * @param bool $appendNewline false for a transport that already frames one message per call
     *                            (syslog()/SyslogUdpHandler), or a trailing "\n" gets escaped by
     *                            rsyslog as a literal "#012" stuck to the JSON
     */
    public function __construct(
        private bool $appendNewline = true,
    ) {
    }

    public function format(LogRecord $record): string
    {
        $document = $record->context + [
            '@timestamp' => $record->datetime->setTimezone(new \DateTimeZone('UTC'))->format(self::DATE_FORMAT),
            'message' => $record->message,
        ];

        return json_encode($document, self::ENCODE_FLAGS).($this->appendNewline ? "\n" : '');
    }

    /**
     * @param array<LogRecord> $records
     *
     * @return list<string>
     */
    public function formatBatch(array $records): array
    {
        return array_values(array_map($this->format(...), $records));
    }
}
