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

namespace IQ2i\VigieBundle\Tests\Processor;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Processor\RequestContextProcessor;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class RequestContextProcessorTest extends TestCase
{
    private function requestEvent(Request $request, bool $isMainRequest = true): RequestEvent
    {
        return new RequestEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            $isMainRequest ? HttpKernelInterface::MAIN_REQUEST : HttpKernelInterface::SUB_REQUEST,
        );
    }

    public function testItIsANoOpWithoutARequest(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $processor = new RequestContextProcessor();

        self::assertSame($activity, $processor($activity));
    }

    public function testASubRequestDoesNotBecomeTheRememberedRequest(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent(Request::create('/admin'), isMainRequest: false));

        self::assertSame($activity, $processor($activity));
    }

    public function testResetForgetsTheRememberedRequest(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent(Request::create('/admin')));
        $processor->reset();

        self::assertSame($activity, $processor($activity));
    }

    public function testItFillsIpAddressAndUserAgentFromTheMainRequest(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $request = Request::create('/', server: ['REMOTE_ADDR' => '203.0.113.1', 'HTTP_USER_AGENT' => 'Symfony']);

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent($request));

        $processed = $processor($activity);

        self::assertSame('203.0.113.1', $processed->ipAddress);
        self::assertSame('Symfony', $processed->userAgent);
    }

    public function testItNeverOverwritesAFieldAlreadySet(): void
    {
        $activity = Activity::security(
            ActivityType::LoginSuccess,
            new \DateTimeImmutable(),
            ipAddress: '198.51.100.1',
        );

        $request = Request::create('/', server: ['REMOTE_ADDR' => '203.0.113.1']);

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent($request));

        $processed = $processor($activity);

        self::assertSame('198.51.100.1', $processed->ipAddress);
    }

    public function testItFillsRequestIdFromTheAttribute(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $request = Request::create('/');
        $request->attributes->set('_vigie_request_id', 'req-1');

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent($request));

        $processed = $processor($activity);

        self::assertSame('req-1', $processed->requestId);
    }

    public function testItFillsHostSchemeAndAuthenticated(): void
    {
        $activity = Activity::httpRequest(
            occurredAt: new \DateTimeImmutable(),
            method: 'GET',
            uri: '/admin',
            statusCode: 200,
        );

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent(Request::create('https://app.example.com/admin')));

        $processed = $processor($activity);

        self::assertSame('app.example.com', $processed->context['host']);
        self::assertSame('https', $processed->context['scheme']);
        self::assertFalse($processed->context['authenticated']);
    }

    public function testItFillsRefererWhenPresent(): void
    {
        $activity = Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 200);

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent(Request::create('/admin', server: ['HTTP_REFERER' => 'https://example.com/'])));

        $processed = $processor($activity);

        self::assertSame('https://example.com/', $processed->context['referer']);
    }

    public function testRefererIsAbsentFromContextWhenTheHeaderIsMissing(): void
    {
        $activity = Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 200);

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent(Request::create('/admin')));

        $processed = $processor($activity);

        self::assertArrayNotHasKey('referer', $processed->context);
    }

    public function testAuthenticatedIsTrueWithATokenCarryingAUser(): void
    {
        $activity = Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 200);

        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $processor = new RequestContextProcessor(tokenStorage: $tokenStorage);
        $processor->onKernelRequest($this->requestEvent(Request::create('/admin')));

        $processed = $processor($activity);

        self::assertTrue($processed->context['authenticated']);
    }

    public function testDurationMsIsComputedFromRequestTimeFloat(): void
    {
        $activity = Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 200);

        $clock = new MockClock('@1000.25');

        $processor = new RequestContextProcessor($clock);
        $processor->onKernelRequest($this->requestEvent(Request::create('/admin', server: ['REQUEST_TIME_FLOAT' => 1_000.0])));

        $processed = $processor($activity);

        self::assertSame(250, $processed->context['duration_ms']);
    }

    public function testDurationMsIsAbsentWhenRequestTimeFloatIsMissing(): void
    {
        $activity = Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 200);

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent(Request::create('/admin', server: ['REQUEST_TIME_FLOAT' => null])));

        $processed = $processor($activity);

        self::assertArrayNotHasKey('duration_ms', $processed->context);
    }

    public function testItFillsTheExceptionClassStampedOnKernelException(): void
    {
        $activity = Activity::httpRequest(new \DateTimeImmutable(), 'GET', '/admin', 500);

        $request = Request::create('/admin');

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent($request));
        $processor->onKernelException(new ExceptionEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            new \RuntimeException('broken'),
        ));

        $processed = $processor($activity);

        self::assertSame(\RuntimeException::class, $processed->context['exception_class']);
    }

    public function testItNeverOverwritesAContextKeyAlreadySet(): void
    {
        $activity = Activity::httpRequest(
            occurredAt: new \DateTimeImmutable(),
            method: 'GET',
            uri: '/admin',
            statusCode: 200,
            context: ['host' => 'already-set', 'authenticated' => true],
        );

        $processor = new RequestContextProcessor();
        $processor->onKernelRequest($this->requestEvent(Request::create('https://app.example.com/admin')));

        $processed = $processor($activity);

        self::assertSame('already-set', $processed->context['host']);
        self::assertTrue($processed->context['authenticated']);
    }
}
