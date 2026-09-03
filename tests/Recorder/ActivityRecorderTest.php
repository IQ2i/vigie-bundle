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

namespace IQ2i\VigieBundle\Tests\Recorder;

use IQ2i\VigieBundle\Event\ActivityRecording;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Model\Subject;
use IQ2i\VigieBundle\Processor\ActivityProcessorInterface;
use IQ2i\VigieBundle\Recorder\ActivityRecorder;
use IQ2i\VigieBundle\Recorder\ActivityRedactor;
use IQ2i\VigieBundle\Recorder\Pseudonymizer;
use IQ2i\VigieBundle\Recorder\Recording;
use IQ2i\VigieBundle\Recorder\RecordingObserverInterface;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use IQ2i\VigieBundle\Recorder\RecordingOutcome;
use IQ2i\VigieBundle\Storage\ActivityStorageInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\MockClock;

final class ActivityRecorderTest extends TestCase
{
    public function testItStoresDirectlyWhenNoBusIsConfigured(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with($activity);

        $recorder = new ActivityRecorder($storage, self::redactor());
        $recorder->record($activity);
    }

    public function testAStorageFailureIsLoggedAndSwallowedRatherThanPropagated(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->method('store')->willThrowException(new \RuntimeException('connection refused'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with(self::stringContains('could not record'), self::callback(
                static fn (array $context): bool => 'connection refused' === $context['message'],
            ));

        $recorder = new ActivityRecorder($storage, self::redactor(), logger: $logger);

        $recorder->record($activity);
    }

    public function testItAppliesRecordingOptionsBeforeStoring(): void
    {
        $activity = Activity::httpRequest(
            occurredAt: new \DateTimeImmutable(),
            method: 'GET',
            uri: '/dashboard',
            route: 'app_dashboard',
            statusCode: 200,
            ipAddress: '203.0.113.1',
        );

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Activity $stored): bool => null === $stored->ipAddress));

        $recorder = new ActivityRecorder($storage, self::redactor(new RecordingOptions(ipAddress: false)));
        $recorder->record($activity);
    }

    public function testTheActivityRecordingEventIsDispatchedBeforeStoring(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())->method('store');

        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::isInstanceOf(ActivityRecording::class))
            ->willReturnArgument(0);

        $recorder = new ActivityRecorder($storage, self::redactor(), dispatcher: $dispatcher);
        $recorder->record($activity);
    }

    public function testAListenerCanEnrichTheContextBeforeStoring(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Activity $stored): bool => 'gold' === ($stored->context['plan'] ?? null)));

        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->method('dispatch')
            ->willReturnCallback(static function (ActivityRecording $event): ActivityRecording {
                $event->addContext('plan', 'gold');

                return $event;
            });

        $recorder = new ActivityRecorder($storage, self::redactor(), dispatcher: $dispatcher);
        $recorder->record($activity);
    }

    public function testCancellingTheEventDiscardsTheActivity(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::never())->method('store');

        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->method('dispatch')
            ->willReturnCallback(static function (ActivityRecording $event): ActivityRecording {
                $event->cancel();

                return $event;
            });

        $recorder = new ActivityRecorder($storage, self::redactor(), $dispatcher);
        $recorder->record($activity);
    }

    public function testAThrowingListenerStillStoresTheUnenrichedActivity(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())->method('store')->with($activity);

        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->method('dispatch')->willThrowException(new \RuntimeException('listener boom'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(self::stringContains('listener failed'), self::callback(
                static fn (array $context): bool => 'listener boom' === $context['message'],
            ));

        $recorder = new ActivityRecorder($storage, self::redactor(), dispatcher: $dispatcher, logger: $logger);

        $recorder->record($activity);
    }

    public function testTheListenerReceivesAnAlreadyRedactedActivity(): void
    {
        $activity = Activity::httpRequest(
            occurredAt: new \DateTimeImmutable(),
            method: 'GET',
            uri: '/dashboard',
            route: 'app_dashboard',
            statusCode: 200,
            ipAddress: '203.0.113.1',
        );

        $storage = $this->createMock(ActivityStorageInterface::class);

        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (ActivityRecording $event): bool {
                self::assertNull($event->getActivity()->ipAddress);

                return true;
            }))
            ->willReturnArgument(0);

        $recorder = new ActivityRecorder($storage, self::redactor(new RecordingOptions(ipAddress: false)), dispatcher: $dispatcher);
        $recorder->record($activity);
    }

    public function testProcessorsRunBeforeRedaction(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Activity $stored): bool => '203.0.113.0' === $stored->ipAddress));

        $processor = new class implements ActivityProcessorInterface {
            public function __invoke(Activity $activity): Activity
            {
                return $activity->withIpAddress('203.0.113.1');
            }
        };

        $recorder = new ActivityRecorder($storage, self::redactor(new RecordingOptions(ipAddress: 'anonymize')), processors: [$processor]);
        $recorder->record($activity);
    }

    public function testAThrowingProcessorStillStoresTheActivityUnaffected(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())->method('store')->with($activity);

        $processor = new class implements ActivityProcessorInterface {
            public function __invoke(Activity $activity): Activity
            {
                throw new \RuntimeException('processor boom');
            }
        };

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(self::stringContains('processor'), self::callback(
                static fn (array $context): bool => 'processor boom' === $context['message'],
            ));

        $recorder = new ActivityRecorder($storage, self::redactor(), processors: [$processor], logger: $logger);

        $recorder->record($activity);
    }

    public function testCustomUsesTheInjectedClockAndProducesACustomActivity(): void
    {
        $now = new \DateTimeImmutable('2026-08-21 10:00:00');

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(self::callback(static function (Activity $stored) use ($now): bool {
                return ActivityType::Custom === $stored->type
                    && 'export.completed' === $stored->action
                    && $now == $stored->occurredAt
                    && ['rows' => 42] === $stored->context;
            }));

        $recorder = new ActivityRecorder($storage, self::redactor(), clock: new MockClock($now));
        $recorder->custom('export.completed', ['rows' => 42]);
    }

    public function testCustomCarriesTheSubject(): void
    {
        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Activity $stored): bool => new Subject('user', 42) == $stored->subject));

        $recorder = new ActivityRecorder($storage, self::redactor());
        $recorder->custom('user.delete', subject: new Subject('user', 42));
    }

    public function testSecurityUsesTheInjectedClockAndProducesASecurityActivity(): void
    {
        $now = new \DateTimeImmutable('2026-08-21 10:00:00');

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(self::callback(static function (Activity $stored) use ($now): bool {
                return ActivityType::RolesChanged === $stored->type
                    && $now == $stored->occurredAt
                    && ['added' => 'ROLE_ADMIN'] === $stored->context;
            }));

        $recorder = new ActivityRecorder($storage, self::redactor(), clock: new MockClock($now));
        $recorder->security(ActivityType::RolesChanged, context: ['added' => 'ROLE_ADMIN']);
    }

    public function testSecurityCarriesTheSubject(): void
    {
        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Activity $stored): bool => new Subject('user', 42) == $stored->subject));

        $recorder = new ActivityRecorder($storage, self::redactor());
        $recorder->security(ActivityType::PasswordChanged, subject: new Subject('user', 42));
    }

    /**
     * @return iterable<string, array{ActivityType}>
     */
    public static function unsupportedSecurityTypeProvider(): iterable
    {
        yield 'custom' => [ActivityType::Custom];
        yield 'http request' => [ActivityType::HttpRequest];
    }

    #[DataProvider('unsupportedSecurityTypeProvider')]
    public function testSecurityRejectsCustomAndHttpRequest(ActivityType $type): void
    {
        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::never())->method('store');

        $recorder = new ActivityRecorder($storage, self::redactor());

        $this->expectException(\InvalidArgumentException::class);
        $recorder->security($type);
    }

    public function testSecurityLeavesANullUserIdentifierForProcessorsToFill(): void
    {
        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Activity $stored): bool => 'jane.doe' === $stored->userIdentifier));

        $processor = new class implements ActivityProcessorInterface {
            public function __invoke(Activity $activity): Activity
            {
                return null === $activity->userIdentifier ? $activity->withUserIdentifier('jane.doe') : $activity;
            }
        };

        $recorder = new ActivityRecorder($storage, self::redactor(), processors: [$processor]);
        $recorder->security(ActivityType::PasswordChanged);
    }

    public function testObserverIsNotifiedOfAStoredOutcome(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);

        $observer = $this->createMock(RecordingObserverInterface::class);
        $observer->expects(self::once())
            ->method('observe')
            ->with(self::callback(static function (Recording $recording) use ($activity): bool {
                self::assertSame($activity, $recording->submitted);
                self::assertInstanceOf(Activity::class, $recording->final);
                self::assertSame(RecordingOutcome::Stored, $recording->outcome);

                return true;
            }));

        $recorder = new ActivityRecorder($storage, self::redactor(), observer: $observer);
        $recorder->record($activity);
    }

    public function testObserverIsNotifiedOfACancelledOutcome(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::never())->method('store');

        $dispatcher = $this->createMock(EventDispatcherInterface::class);
        $dispatcher->method('dispatch')
            ->willReturnCallback(static function (ActivityRecording $event): ActivityRecording {
                $event->cancel();

                return $event;
            });

        $observer = $this->createMock(RecordingObserverInterface::class);
        $observer->expects(self::once())
            ->method('observe')
            ->with(self::callback(static function (Recording $recording) use ($activity): bool {
                self::assertSame($activity, $recording->submitted);
                self::assertNull($recording->final);
                self::assertSame(RecordingOutcome::Cancelled, $recording->outcome);

                return true;
            }));

        $recorder = new ActivityRecorder($storage, self::redactor(), dispatcher: $dispatcher, observer: $observer);
        $recorder->record($activity);
    }

    public function testObserverIsNotifiedOfAFailedOutcome(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->method('store')->willThrowException(new \RuntimeException('connection refused'));

        $observer = $this->createMock(RecordingObserverInterface::class);
        $observer->expects(self::once())
            ->method('observe')
            ->with(self::callback(static function (Recording $recording) use ($activity): bool {
                self::assertSame($activity, $recording->submitted);
                self::assertNull($recording->final);
                self::assertSame(RecordingOutcome::Failed, $recording->outcome);

                return true;
            }));

        $recorder = new ActivityRecorder($storage, self::redactor(), observer: $observer);
        $recorder->record($activity);
    }

    public function testAThrowingObserverDoesNotAffectRecording(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $storage = $this->createMock(ActivityStorageInterface::class);
        $storage->expects(self::once())->method('store')->with($activity);

        $observer = $this->createMock(RecordingObserverInterface::class);
        $observer->method('observe')->willThrowException(new \RuntimeException('observer boom'));

        $recorder = new ActivityRecorder($storage, self::redactor(), observer: $observer);

        $recorder->record($activity);
    }

    private static function redactor(?RecordingOptions $options = null): ActivityRedactor
    {
        return new ActivityRedactor($options ?? new RecordingOptions(), new Pseudonymizer('test-secret'));
    }
}
