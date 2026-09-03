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

namespace IQ2i\VigieBundle\Tests\EventSubscriber;

use IQ2i\VigieBundle\EventSubscriber\HttpActivitySubscriber;
use IQ2i\VigieBundle\EventSubscriber\ThreatEnforcementSubscriber;
use IQ2i\VigieBundle\EventSubscriber\TrackingAttributeSubscriber;
use IQ2i\VigieBundle\Http\TrackingDecider;
use IQ2i\VigieBundle\Http\TrackingDecision;
use IQ2i\VigieBundle\Http\TrackingSource;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Model\Subject;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class HttpActivitySubscriberTest extends TestCase
{
    public function testItRecordsTheHttpRequestOnTerminate(): void
    {
        $occurredAt = new \DateTimeImmutable('2026-08-21 10:00:00');

        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity) use ($occurredAt): bool {
                self::assertSame(ActivityType::HttpRequest, $activity->type);
                self::assertEquals($occurredAt, $activity->occurredAt);
                self::assertSame('GET', $activity->method);
                self::assertSame('/dashboard', $activity->uri);
                self::assertSame('app_dashboard', $activity->route);
                self::assertSame(200, $activity->statusCode);
                self::assertSame('jane.doe', $activity->userIdentifier);

                return true;
            }));

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock($occurredAt), $tokenStorage);

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);

        // Nothing is recorded on kernel.response; only captured; the
        // "expects(once)" above is only satisfied by the terminate call.
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testItDoesNotRecordAnythingWithoutATerminateEvent(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::never())->method('record');

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $subscriber->onKernelResponse($this->responseEvent('/dashboard', 'app_dashboard', 200, true));
    }

    public function testItIgnoresSubRequests(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::never())->method('record');

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, false);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testNothingIsRecordedByDefault(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::never())->method('record');

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testTrackActionAloneImpliesRecording(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('admin.delete', $activity->action);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true);
        $event->getRequest()->attributes->set(TrackingAttributeSubscriber::ATTRIBUTE, true);
        $event->getRequest()->attributes->set(TrackingAttributeSubscriber::ACTION_ATTRIBUTE, 'admin.delete');
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testTrackActionAttributeOverridesTheRecordedAction(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('admin.dashboard', $activity->action);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $event->getRequest()->attributes->set(TrackingAttributeSubscriber::ACTION_ATTRIBUTE, 'admin.dashboard');
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testItRecordsTheFirewallName(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('main', $activity->firewall);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $event->getRequest()->attributes->set('_firewall_context', 'security.firewall.map.context.main');

        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testQueryStringIsStrippedByDefault(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('/dashboard', $activity->uri);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard?token=secret', 'app_dashboard', 200, true, tracked: true);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testQueryStringIsKeptWhenConfigured(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('/dashboard?token=secret', $activity->uri);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber(
            $recorder,
            new MockClock(),
            queryString: true,
        );

        $event = $this->responseEvent('/dashboard?token=secret', 'app_dashboard', 200, true, tracked: true);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testABuildFailureIsLoggedAndDoesNotBreakTheResponse(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error');

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willThrowException(new \RuntimeException('boom'));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock(), $tokenStorage, logger: $logger);

        $subscriber->onKernelResponse($this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true));
    }

    public function testARecordFailureIsLoggedAndDoesNotPropagate(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->method('record')->willThrowException(new \RuntimeException('boom'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error');

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock(), logger: $logger);

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $subscriber->onKernelResponse($event);

        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testAPendingActivityFromAnIgnoredRequestDoesNotLeakIntoTheNextTerminate(): void
    {
        // In a worker runtime, this subscriber instance survives across
        // requests. A request that returns early from onKernelResponse()
        // (an ignored path here) must not leave a stale $pending that a
        // later, unrelated onKernelTerminate() call would record.
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::never())->method('record');

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock(), decider: new TrackingDecider(ignoredPaths: ['^/_']));

        $ignoredEvent = $this->responseEvent('/_profiler/abc123', null, 200, true);
        $subscriber->onKernelResponse($ignoredEvent);

        $unrelatedEvent = $this->responseEvent('/_profiler/def456', null, 200, true);
        $subscriber->onKernelTerminate($this->terminateEvent($unrelatedEvent));
    }

    public function testResetClearsThePendingActivity(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::never())->method('record');

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $subscriber->onKernelResponse($event);

        // Simulates a worker runtime resetting every ResetInterface service
        // between requests, independently of the response/terminate cycle.
        $subscriber->reset();

        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testItImplementsResetInterface(): void
    {
        $subscriber = new HttpActivitySubscriber($this->createMock(ActivityRecorderInterface::class), new MockClock());

        self::assertInstanceOf(\Symfony\Contracts\Service\ResetInterface::class, $subscriber);
    }

    public function testImpersonatorIsRecordedWhenSwitchUserTokenIsActive(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('admin', $activity->context['impersonator'] ?? null);

                return true;
            }));

        $original = new UsernamePasswordToken(new InMemoryUser('admin', null), 'main');
        $switchUserToken = new SwitchUserToken(new InMemoryUser('jane.doe', null), 'main', ['ROLE_USER'], $original);

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($switchUserToken);

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock(), $tokenStorage);

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testSessionIdIsNullWhenNoSessionWasStarted(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertNull($activity->sessionId);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testRequestIdIsReadFromAttributes(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('req-123', $activity->requestId);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $event->getRequest()->attributes->set('_vigie_request_id', 'req-123');
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testSubjectIsReadFromAttributes(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertEquals(new Subject('user', '42'), $activity->subject);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $event->getRequest()->attributes->set(TrackingAttributeSubscriber::SUBJECT_ATTRIBUTE, new Subject('user', 42));
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testRouteParamsAreCopiedIntoContextWhenEnabled(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame(42, $activity->context['id']);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock(), routeParams: true);

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $event->getRequest()->attributes->set('_route_params', ['id' => 42]);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testRouteParamsAreNotCopiedByDefault(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertArrayNotHasKey('id', $activity->context);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $event->getRequest()->attributes->set('_route_params', ['id' => 42]);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testRouteParamsNeverOverwriteAnExistingContextKey(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('admin', $activity->context['impersonator']);

                return true;
            }));

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $originalToken = new UsernamePasswordToken(new InMemoryUser('admin', null), 'main');
        $tokenStorage->method('getToken')->willReturn(new SwitchUserToken(new InMemoryUser('jane.doe', null), 'main', ['ROLE_USER'], $originalToken));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock(), $tokenStorage, routeParams: true);

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true, tracked: true);
        $event->getRequest()->attributes->set('_route_params', ['impersonator' => 'someone-else']);
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testTheEnforcedRemediationIsRecorded(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('ban', $activity->remediation);

                return true;
            }));

        $subscriber = new HttpActivitySubscriber($recorder, new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 403, true, tracked: true);
        $event->getRequest()->attributes->set(ThreatEnforcementSubscriber::ATTRIBUTE, 'ban');
        $subscriber->onKernelResponse($event);
        $subscriber->onKernelTerminate($this->terminateEvent($event));
    }

    public function testDecisionSourceIsDefaultWhenNothingMatches(): void
    {
        $subscriber = new HttpActivitySubscriber($this->createMock(ActivityRecorderInterface::class), new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, true);
        $subscriber->onKernelResponse($event);

        $decision = $event->getRequest()->attributes->get('_vigie_decision');
        self::assertInstanceOf(TrackingDecision::class, $decision);
        self::assertFalse($decision->recorded);
        self::assertSame(TrackingSource::Default, $decision->source);
    }

    public function testDecisionSourceIsNotMainRequestForASubRequest(): void
    {
        $subscriber = new HttpActivitySubscriber($this->createMock(ActivityRecorderInterface::class), new MockClock());

        $event = $this->responseEvent('/dashboard', 'app_dashboard', 200, false);
        $subscriber->onKernelResponse($event);

        $decision = $event->getRequest()->attributes->get('_vigie_decision');
        self::assertInstanceOf(TrackingDecision::class, $decision);
        self::assertFalse($decision->recorded);
        self::assertSame(TrackingSource::NotMainRequest, $decision->source);
    }

    private function responseEvent(string $path, ?string $route, int $statusCode, bool $isMainRequest, string $method = 'GET', ?bool $tracked = null): ResponseEvent
    {
        $request = Request::create($path, $method);

        if (null !== $route) {
            $request->attributes->set('_route', $route);
        }

        if (null !== $tracked) {
            $request->attributes->set(TrackingAttributeSubscriber::ATTRIBUTE, $tracked);
        }

        $kernel = $this->createMock(HttpKernelInterface::class);

        return new ResponseEvent(
            $kernel,
            $request,
            $isMainRequest ? HttpKernelInterface::MAIN_REQUEST : HttpKernelInterface::SUB_REQUEST,
            new Response('', $statusCode),
        );
    }

    private function terminateEvent(ResponseEvent $responseEvent): TerminateEvent
    {
        return new TerminateEvent(
            $responseEvent->getKernel(),
            $responseEvent->getRequest(),
            $responseEvent->getResponse(),
        );
    }
}
