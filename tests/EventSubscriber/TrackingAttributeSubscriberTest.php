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

use IQ2i\VigieBundle\Attribute\Track;
use IQ2i\VigieBundle\Attribute\Untrack;
use IQ2i\VigieBundle\EventSubscriber\TrackingAttributeSubscriber;
use IQ2i\VigieBundle\Model\Subject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class TrackingAttributeSubscriberTest extends TestCase
{
    public function testControllerWithoutAnyAttributeIsNotStamped(): void
    {
        $event = $this->controllerEvent([new PlainController(), 'index']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertFalse($event->getRequest()->attributes->has(TrackingAttributeSubscriber::ATTRIBUTE));
    }

    public function testUntrackOnTheClassIsApplied(): void
    {
        $event = $this->controllerEvent([new UntrackedController(), 'index']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertFalse($event->getRequest()->attributes->get(TrackingAttributeSubscriber::ATTRIBUTE));
    }

    public function testTrackOnTheMethodOverridesUntrackOnTheClass(): void
    {
        $event = $this->controllerEvent([new UntrackedController(), 'reactivated']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertTrue($event->getRequest()->attributes->get(TrackingAttributeSubscriber::ATTRIBUTE));
    }

    public function testUntrackOnTheMethodOverridesTrackOnTheClass(): void
    {
        $event = $this->controllerEvent([new TrackedController(), 'deactivated']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertFalse($event->getRequest()->attributes->get(TrackingAttributeSubscriber::ATTRIBUTE));
    }

    public function testTrackOnTheClassIsAppliedWhenTheMethodHasNoAttribute(): void
    {
        $event = $this->controllerEvent([new TrackedController(), 'plain']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertTrue($event->getRequest()->attributes->get(TrackingAttributeSubscriber::ATTRIBUTE));
    }

    public function testAnInvokableControllerReadsItsOwnAttributes(): void
    {
        $event = $this->controllerEvent(new InvokableUntrackedController());

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertFalse($event->getRequest()->attributes->get(TrackingAttributeSubscriber::ATTRIBUTE));
    }

    public function testAClosureControllerCanBeMarkedUntrack(): void
    {
        $event = $this->controllerEvent(#[Untrack] static function (): void {});

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertFalse($event->getRequest()->attributes->get(TrackingAttributeSubscriber::ATTRIBUTE));
    }

    public function testConflictingAttributesOnTheSameMethodThrow(): void
    {
        $this->expectException(\LogicException::class);

        $event = $this->controllerEvent([new ConflictingController(), 'index']);

        (new TrackingAttributeSubscriber())->onKernelController($event);
    }

    public function testTrackWithoutAnActionDoesNotStampTheActionAttribute(): void
    {
        $event = $this->controllerEvent([new TrackedController(), 'plain']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertFalse($event->getRequest()->attributes->has(TrackingAttributeSubscriber::ACTION_ATTRIBUTE));
    }

    public function testTrackWithAnActionOnTheMethodStampsIt(): void
    {
        $event = $this->controllerEvent([new ActionOverrideController(), 'delete']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertSame('delete', $event->getRequest()->attributes->get(TrackingAttributeSubscriber::ACTION_ATTRIBUTE));
    }

    public function testTrackActionsOnTheClassAndTheMethodAreCombined(): void
    {
        $event = $this->controllerEvent([new CombinedActionController(), 'delete']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertSame('admin.delete', $event->getRequest()->attributes->get(TrackingAttributeSubscriber::ACTION_ATTRIBUTE));
    }

    public function testTrackActionOnTheClassAloneIsUsedWhenTheMethodHasNone(): void
    {
        $event = $this->controllerEvent([new CombinedActionController(), 'plain']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertSame('admin.', $event->getRequest()->attributes->get(TrackingAttributeSubscriber::ACTION_ATTRIBUTE));
    }

    public function testCombinedActionsAreJoinedByADotWhenTheClassActionHasNoTrailingOne(): void
    {
        $event = $this->controllerEvent([new CombinedActionNoDotController(), 'delete']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertSame('admin.delete', $event->getRequest()->attributes->get(TrackingAttributeSubscriber::ACTION_ATTRIBUTE));
    }

    public function testCombinedActionsAreNotDoubleDottedWhenTheClassActionAlreadyEndsWithOne(): void
    {
        $event = $this->controllerEvent([new CombinedActionController(), 'delete']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertSame('admin.delete', $event->getRequest()->attributes->get(TrackingAttributeSubscriber::ACTION_ATTRIBUTE));
    }

    public function testTrackWithASubjectReadsTheIdFromTheDefaultRouteParam(): void
    {
        $event = $this->controllerEvent([new SubjectController(), 'delete'], ['id' => 42]);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertEquals(new Subject('user', '42'), $event->getRequest()->attributes->get(TrackingAttributeSubscriber::SUBJECT_ATTRIBUTE));
    }

    public function testTrackWithASubjectAndNoMatchingRouteParamDoesNotStampASubject(): void
    {
        $event = $this->controllerEvent([new SubjectController(), 'delete'], []);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertFalse($event->getRequest()->attributes->has(TrackingAttributeSubscriber::SUBJECT_ATTRIBUTE));
    }

    public function testTrackWithACustomSubjectParamReadsThatParam(): void
    {
        $event = $this->controllerEvent([new CustomSubjectParamController(), 'delete'], ['uuid' => 'abc-123']);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertEquals(new Subject('user', 'abc-123'), $event->getRequest()->attributes->get(TrackingAttributeSubscriber::SUBJECT_ATTRIBUTE));
    }

    public function testMethodSubjectWinsOverClassSubject(): void
    {
        $event = $this->controllerEvent([new CombinedSubjectController(), 'delete'], ['id' => 42]);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertEquals(new Subject('order', '42'), $event->getRequest()->attributes->get(TrackingAttributeSubscriber::SUBJECT_ATTRIBUTE));
    }

    public function testClassSubjectIsUsedWhenTheMethodHasNone(): void
    {
        $event = $this->controllerEvent([new CombinedSubjectController(), 'plain'], ['id' => 42]);

        (new TrackingAttributeSubscriber())->onKernelController($event);

        self::assertEquals(new Subject('user', '42'), $event->getRequest()->attributes->get(TrackingAttributeSubscriber::SUBJECT_ATTRIBUTE));
    }

    /**
     * @param array<string, mixed> $routeParams
     */
    private function controllerEvent(callable $controller, array $routeParams = []): ControllerEvent
    {
        $request = Request::create('/');
        $request->attributes->set('_route_params', $routeParams);

        return new ControllerEvent(
            $this->createMock(HttpKernelInterface::class),
            $controller,
            $request,
            HttpKernelInterface::MAIN_REQUEST,
        );
    }
}

final class PlainController
{
    public function index(): void
    {
    }
}

#[Untrack]
final class UntrackedController
{
    public function index(): void
    {
    }

    #[Track]
    public function reactivated(): void
    {
    }
}

#[Track]
final class TrackedController
{
    public function plain(): void
    {
    }

    #[Untrack]
    public function deactivated(): void
    {
    }
}

#[Untrack]
final class InvokableUntrackedController
{
    public function __invoke(): void
    {
    }
}

final class ConflictingController
{
    #[Track]
    #[Untrack]
    public function index(): void
    {
    }
}

final class ActionOverrideController
{
    #[Track('delete')]
    public function delete(): void
    {
    }
}

#[Track('admin.')]
final class CombinedActionController
{
    #[Track('delete')]
    public function delete(): void
    {
    }

    public function plain(): void
    {
    }
}

#[Track('admin')]
final class CombinedActionNoDotController
{
    #[Track('delete')]
    public function delete(): void
    {
    }
}

final class SubjectController
{
    #[Track('user.delete', subject: 'user')]
    public function delete(): void
    {
    }
}

final class CustomSubjectParamController
{
    #[Track('user.delete', subject: 'user', subjectParam: 'uuid')]
    public function delete(): void
    {
    }
}

#[Track(subject: 'user')]
final class CombinedSubjectController
{
    #[Track(subject: 'order')]
    public function delete(): void
    {
    }

    public function plain(): void
    {
    }
}
