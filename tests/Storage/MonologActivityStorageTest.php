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

namespace IQ2i\VigieBundle\Tests\Storage;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Monolog\EcsDocument;
use IQ2i\VigieBundle\Storage\MonologActivityStorage;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\MockClock;

/**
 * @phpstan-import-type EcsDocumentShape from EcsDocument
 */
final class MonologActivityStorageTest extends TestCase
{
    public function testStoreLogsAnInfoRecordWithTheEcsDocumentAsContext(): void
    {
        $now = new \DateTimeImmutable('2026-08-21 10:00:01');
        $activity = Activity::security(
            type: ActivityType::LoginSuccess,
            occurredAt: new \DateTimeImmutable('2026-08-21 10:00:00'),
            userIdentifier: 'jane.doe',
        );

        $expectedDocument = EcsDocument::fromActivity($activity, $now, 'shop', 'prod');
        $expectedMessage = EcsDocument::message($activity);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('info')
            ->with($expectedMessage, $expectedDocument);

        $storage = new MonologActivityStorage($logger, new MockClock($now), app: 'shop', env: 'prod');
        $storage->store($activity);
    }

    public function testRecordedAtUsesTheClockNotOccurredAt(): void
    {
        $activity = Activity::custom('export.completed', new \DateTimeImmutable('2026-08-21 10:00:00'));
        $now = new \DateTimeImmutable('2026-08-21 10:05:00');

        $assertRecordedAtAndTimestamp = static function (array $document): bool {
            /** @var EcsDocumentShape $typed */
            $typed = $document;
            self::assertStringStartsWith('2026-08-21T10:05:00', $typed['event']['created']);
            self::assertStringStartsWith('2026-08-21T10:00:00', $typed['@timestamp']);

            return true;
        };

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('info')
            ->with(self::anything(), self::callback($assertRecordedAtAndTimestamp));

        $storage = new MonologActivityStorage($logger, new MockClock($now));
        $storage->store($activity);
    }
}
