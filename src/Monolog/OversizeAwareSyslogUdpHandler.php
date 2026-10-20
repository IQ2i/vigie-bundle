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

use Monolog\Handler\SyslogUdpHandler;
use Monolog\LogRecord;
use Psr\Log\LoggerInterface;

/**
 * A SyslogUdpHandler that says so when it truncates a document. UdpSocket silently cuts a line to
 * maxLength minus its header, and a truncated ECS line is invalid JSON the collector never parses: the
 * activity is lost with no trace on either side.
 *
 * Reports through the application's own logger, never through the vigie.activity channel this handler
 * serves, and never includes the document itself.
 *
 * @internal
 */
final class OversizeAwareSyslogUdpHandler extends SyslogUdpHandler
{
    public function __construct(
        string $host,
        int $port,
        string|int $facility,
        string $ident,
        private readonly int $limit,
        private readonly ?LoggerInterface $logger = null,
    ) {
        parent::__construct($host, $port, $facility, ident: $ident, maxLength: $limit);
    }

    protected function write(LogRecord $record): void
    {
        $header = $this->makeCommonSyslogHeader($this->toSyslogPriority($record->level), $record->datetime);
        $formatted = $record->formatted;
        $size = \strlen($header) + \strlen(rtrim(\is_string($formatted) ? $formatted : '', "\r\n"));

        if ($size > $this->limit) {
            $event = $record->context['event'] ?? null;
            $vigie = $record->context['vigie'] ?? null;

            $this->logger?->warning('Vigie syslog datagram of {size} bytes exceeds output.syslog.max_length ({max_length}) and is truncated into invalid JSON: raise max_length, and the collector\'s own limit with it.', [
                'size' => $size,
                'max_length' => $this->limit,
                'event_id' => \is_array($event) ? ($event['id'] ?? null) : null,
                'type' => \is_array($vigie) ? ($vigie['type'] ?? null) : null,
            ]);
        }

        parent::write($record);
    }
}
