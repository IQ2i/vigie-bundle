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
use IQ2i\VigieBundle\Monolog\OversizeAwareSyslogUdpHandler;
use IQ2i\VigieBundle\Tests\TestApplication\CollectingLogger;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;

final class OversizeAwareSyslogUdpHandlerTest extends TestCase
{
    private CollectingLogger $logger;

    private RecordingUdpSocket $socket;

    protected function setUp(): void
    {
        if (!\extension_loaded('sockets')) {
            self::markTestSkipped('ext-sockets is required by SyslogUdpHandler.');
        }

        $this->logger = new CollectingLogger();
        $this->socket = new RecordingUdpSocket('127.0.0.1', 514);
    }

    private function handler(int $maxLength): OversizeAwareSyslogUdpHandler
    {
        $handler = new OversizeAwareSyslogUdpHandler('127.0.0.1', 514, 'local0', 'vigie', $maxLength, $this->logger);
        $handler->setFormatter(new EcsFormatter(false));

        // The socket is what truncates: it must carry the same limit as the handler.
        $this->socket = new RecordingUdpSocket('127.0.0.1', 514, $maxLength);
        $handler->setSocket($this->socket);

        return $handler;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function record(array $context): LogRecord
    {
        return new LogRecord(new \DateTimeImmutable(), 'vigie.activity', Level::Info, 'http_request GET /ping', $context);
    }

    public function testALineThatFitsIsSentWithoutAWarning(): void
    {
        $this->handler(8192)->handle($this->record(['vigie' => ['type' => 'http_request']]));

        self::assertCount(1, $this->socket->sent);
        self::assertSame([], $this->logger->records);
    }

    public function testATruncatedLineIsReportedWithoutItsContent(): void
    {
        $this->handler(300)->handle($this->record([
            'event' => ['id' => '01926f5e'],
            'vigie' => ['type' => 'http_request', 'context' => ['secret' => str_repeat('x', 1000)]],
        ]));

        self::assertCount(1, $this->socket->sent);
        self::assertLessThanOrEqual(300, \strlen($this->socket->sent[0]));

        self::assertCount(1, $this->logger->records);
        $warning = $this->logger->records[0];
        self::assertSame('warning', $warning['level']);
        self::assertSame('01926f5e', $warning['context']['event_id']);
        self::assertSame('http_request', $warning['context']['type']);
        self::assertSame(300, $warning['context']['max_length']);
        self::assertStringNotContainsString('xxxx', json_encode($warning, \JSON_THROW_ON_ERROR));
    }

    public function testItStillWorksWithoutALogger(): void
    {
        $handler = new OversizeAwareSyslogUdpHandler('127.0.0.1', 514, 'local0', 'vigie', 100);
        $handler->setFormatter(new EcsFormatter(false));
        $handler->setSocket($this->socket);

        $handler->handle($this->record(['vigie' => ['context' => str_repeat('x', 500)]]));

        self::assertCount(1, $this->socket->sent);
    }
}
