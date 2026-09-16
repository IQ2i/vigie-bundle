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

namespace IQ2i\VigieBundle\Tests\Messenger;

use IQ2i\VigieBundle\Messenger\ActivityContextMiddleware;
use IQ2i\VigieBundle\Messenger\ActivityContextStamp;
use IQ2i\VigieBundle\Model\Activity;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Middleware\MiddlewareInterface;
use Symfony\Component\Messenger\Middleware\StackMiddleware;
use Symfony\Component\Messenger\Stamp\ReceivedStamp;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class ActivityContextMiddlewareTest extends TestCase
{
    private function requestStackWith(?Request $request): RequestStack
    {
        $stack = new RequestStack();

        if (null !== $request) {
            $stack->push($request);
        }

        return $stack;
    }

    public function testDispatchSideIsANoOpWithoutARequest(): void
    {
        $middleware = new ActivityContextMiddleware($this->requestStackWith(null));
        $envelope = new Envelope(new \stdClass());

        $result = $middleware->handle($envelope, new StackMiddleware($this->passThrough()));

        self::assertNull($result->last(ActivityContextStamp::class));
    }

    public function testDispatchSideStampsTheEnvelopeFromTheRequestAndToken(): void
    {
        $request = Request::create('/');
        $request->attributes->set('_vigie_request_id', 'req-1');

        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $middleware = new ActivityContextMiddleware($this->requestStackWith($request), $tokenStorage);
        $envelope = new Envelope(new \stdClass());

        $result = $middleware->handle($envelope, new StackMiddleware($this->passThrough()));

        $stamp = $result->last(ActivityContextStamp::class);
        self::assertNotNull($stamp);
        self::assertSame('req-1', $stamp->requestId);
        self::assertSame('jane.doe', $stamp->userIdentifier);
    }

    public function testDispatchSideNeverOverwritesAnExistingStamp(): void
    {
        $request = Request::create('/');
        $request->attributes->set('_vigie_request_id', 'req-1');

        $middleware = new ActivityContextMiddleware($this->requestStackWith($request));
        $original = new ActivityContextStamp(requestId: 'already-set');
        $envelope = new Envelope(new \stdClass(), [$original]);

        $result = $middleware->handle($envelope, new StackMiddleware($this->passThrough()));

        self::assertSame($original, $result->last(ActivityContextStamp::class));
    }

    public function testWorkerSideExposesTheStampToTheProcessorForTheDurationOfHandle(): void
    {
        $middleware = new ActivityContextMiddleware($this->requestStackWith(null));
        $envelope = new Envelope(new \stdClass(), [
            new ReceivedStamp('transport'),
            new ActivityContextStamp(requestId: 'req-1', userIdentifier: 'jane.doe'),
        ]);

        $probe = new ActivityCapturingMiddleware($middleware, Activity::custom('worker.job', new \DateTimeImmutable()));

        $middleware->handle($envelope, new StackMiddleware($probe));

        self::assertNotNull($probe->captured);
        self::assertSame('req-1', $probe->captured->requestId);
        self::assertSame('jane.doe', $probe->captured->userIdentifier);

        // The window is over: the stamp must not leak into activities recorded after handle() returns.
        $after = $middleware(Activity::custom('after.handle', new \DateTimeImmutable()));
        self::assertNull($after->requestId);
    }

    public function testWorkerSideNeverOverwritesFieldsAlreadySetOnTheActivity(): void
    {
        $middleware = new ActivityContextMiddleware($this->requestStackWith(null));
        $envelope = new Envelope(new \stdClass(), [
            new ReceivedStamp('transport'),
            new ActivityContextStamp(requestId: 'req-1', userIdentifier: 'jane.doe'),
        ]);

        $probe = new ActivityCapturingMiddleware(
            $middleware,
            Activity::custom('worker.job', new \DateTimeImmutable(), userIdentifier: 'john.doe'),
        );

        $middleware->handle($envelope, new StackMiddleware($probe));

        self::assertNotNull($probe->captured);
        self::assertSame('john.doe', $probe->captured->userIdentifier);
        self::assertSame('req-1', $probe->captured->requestId);
    }

    public function testWorkerSideClearsTheStampEvenIfTheHandlerThrows(): void
    {
        $middleware = new ActivityContextMiddleware($this->requestStackWith(null));
        $envelope = new Envelope(new \stdClass(), [
            new ReceivedStamp('transport'),
            new ActivityContextStamp(requestId: 'req-1'),
        ]);

        $throwing = $this->createMock(MiddlewareInterface::class);
        $throwing->method('handle')->willThrowException(new \RuntimeException('handler failed'));

        try {
            $middleware->handle($envelope, new StackMiddleware($throwing));
            self::fail('Expected the exception to propagate.');
        } catch (\RuntimeException) {
            // expected
        }

        $after = $middleware(Activity::custom('after.failure', new \DateTimeImmutable()));
        self::assertNull($after->requestId);
    }

    public function testProcessorIsANoOpWithoutAStamp(): void
    {
        $middleware = new ActivityContextMiddleware($this->requestStackWith(null));
        $activity = Activity::custom('some.job', new \DateTimeImmutable());

        self::assertSame($activity, $middleware($activity));
    }

    public function testResetClearsTheStamp(): void
    {
        $middleware = new ActivityContextMiddleware($this->requestStackWith(null));
        $envelope = new Envelope(new \stdClass(), [
            new ReceivedStamp('transport'),
            new ActivityContextStamp(requestId: 'req-1'),
        ]);

        $middleware->handle($envelope, new StackMiddleware($this->passThrough()));
        $middleware->reset();

        $activity = $middleware(Activity::custom('some.job', new \DateTimeImmutable()));
        self::assertNull($activity->requestId);
    }

    private function passThrough(): MiddlewareInterface
    {
        $middleware = $this->createMock(MiddlewareInterface::class);
        $middleware->method('handle')->willReturnCallback(static fn (Envelope $envelope): Envelope => $envelope);

        return $middleware;
    }
}
