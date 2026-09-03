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

use IQ2i\VigieBundle\EventSubscriber\RequestIdSubscriber;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class RequestIdSubscriberTest extends TestCase
{
    private function requestEvent(Request $request, bool $isMainRequest = true): RequestEvent
    {
        return new RequestEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            $isMainRequest ? HttpKernelInterface::MAIN_REQUEST : HttpKernelInterface::SUB_REQUEST,
        );
    }

    public function testItGeneratesARequestIdWhenNoHeaderIsConfigured(): void
    {
        $subscriber = new RequestIdSubscriber();
        $request = Request::create('/');

        $subscriber->onKernelRequest($this->requestEvent($request));

        $id = $request->attributes->get('_vigie_request_id');
        self::assertIsString($id);
        self::assertNotSame('', $id);
    }

    public function testATrustedHeaderIsUsedAsIs(): void
    {
        $subscriber = new RequestIdSubscriber('X-Request-Id');
        $request = Request::create('/');
        $request->headers->set('X-Request-Id', 'abc-123.def_456');

        $subscriber->onKernelRequest($this->requestEvent($request));

        self::assertSame('abc-123.def_456', $request->attributes->get('_vigie_request_id'));
    }

    public function testAnInvalidHeaderValueIsRegenerated(): void
    {
        $subscriber = new RequestIdSubscriber('X-Request-Id');
        $request = Request::create('/');
        $request->headers->set('X-Request-Id', "../../etc/passwd\n".str_repeat('a', 300));

        $subscriber->onKernelRequest($this->requestEvent($request));

        $id = $request->attributes->get('_vigie_request_id');
        self::assertIsString($id);
        self::assertNotSame("../../etc/passwd\n".str_repeat('a', 300), $id);
    }

    public function testTheHeaderIsIgnoredWhenNoneIsConfigured(): void
    {
        $subscriber = new RequestIdSubscriber(null);
        $request = Request::create('/');
        $request->headers->set('X-Request-Id', 'client-supplied');

        $subscriber->onKernelRequest($this->requestEvent($request));

        self::assertNotSame('client-supplied', $request->attributes->get('_vigie_request_id'));
    }

    public function testASubRequestIsNotStamped(): void
    {
        $subscriber = new RequestIdSubscriber();
        $request = Request::create('/');

        $subscriber->onKernelRequest($this->requestEvent($request, isMainRequest: false));

        self::assertFalse($request->attributes->has('_vigie_request_id'));
    }
}
