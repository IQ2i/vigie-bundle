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

use IQ2i\VigieBundle\Event\ThreatDecisionMatched;
use IQ2i\VigieBundle\EventSubscriber\ThreatEnforcementSubscriber;
use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use IQ2i\VigieBundle\Tests\TestApplication\CollectingLogger;
use IQ2i\VigieBundle\Threat\ThreatChecker;
use IQ2i\VigieBundle\Threat\ThreatCheckerInterface;
use IQ2i\VigieBundle\Threat\ThreatSubject;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Exception\RouteNotFoundException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class ThreatEnforcementSubscriberTest extends TestCase
{
    // Ip decisions exercise the network stage (onNetworkStage): no token storage involved.
    private function ipBanStore(): InMemoryThreatDecisionStore
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::ip(), '127.0.0.1', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        return $store;
    }

    private function checker(?InMemoryThreatDecisionStore $store = null): ThreatCheckerInterface
    {
        return new ThreatChecker($store ?? $this->ipBanStore(), clock: new MockClock('2026-08-21 10:00:00'));
    }

    private static function response(RequestEvent $event): Response
    {
        $response = $event->getResponse();
        self::assertInstanceOf(Response::class, $response);

        return $response;
    }

    private function requestEvent(string $path, ?string $route = null, bool $isMainRequest = true): RequestEvent
    {
        $request = Request::create($path);

        if (null !== $route) {
            $request->attributes->set('_route', $route);
        }

        return new RequestEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            $isMainRequest ? HttpKernelInterface::MAIN_REQUEST : HttpKernelInterface::SUB_REQUEST,
        );
    }

    /**
     * @return iterable<string, array{array<string, int|string>, ?int}>
     */
    public static function remediationTables(): iterable
    {
        yield 'a status code for the matching type' => [['ban' => 403], 403];
        yield 'a type absent from the table is never acted on' => [['captcha' => 'app_captcha'], null];
    }

    /**
     * @param array<string, int|string> $remediations
     */
    #[DataProvider('remediationTables')]
    public function testTheTableTurnsTheHighestDecisionIntoAResponse(array $remediations, ?int $expectedStatus): void
    {
        $subscriber = new ThreatEnforcementSubscriber($this->checker(), $remediations);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        if (null === $expectedStatus) {
            self::assertFalse($event->hasResponse());
            self::assertNull($event->getRequest()->attributes->get(ThreatEnforcementSubscriber::ATTRIBUTE));

            return;
        }

        self::assertSame($expectedStatus, self::response($event)->getStatusCode());
        self::assertSame('ban', $event->getRequest()->attributes->get(ThreatEnforcementSubscriber::ATTRIBUTE));
    }

    public function testACaptchaRemediationRedirectsToTheGeneratedRoute(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::ip(), '127.0.0.1', 'captcha', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $urlGenerator = $this->createMock(UrlGeneratorInterface::class);
        $urlGenerator->method('generate')->with('app_captcha')->willReturn('/captcha');

        $subscriber = new ThreatEnforcementSubscriber($this->checker($store), ['captcha' => 'app_captcha'], urlGenerator: $urlGenerator);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        $response = self::response($event);
        self::assertSame(302, $response->getStatusCode());
        self::assertSame('/captcha', $response->headers->get('Location'));
    }

    public function testNoDecisionLeavesTheRequestAlone(): void
    {
        $subscriber = new ThreatEnforcementSubscriber($this->checker(new InMemoryThreatDecisionStore()), ['ban' => 403]);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        self::assertFalse($event->hasResponse());
    }

    public function testTheEventIsDispatchedEvenWhenTheTableHasNoEntryForTheType(): void
    {
        $dispatcher = new EventDispatcher();
        $observed = null;
        $dispatcher->addListener(ThreatDecisionMatched::class, static function (ThreatDecisionMatched $event) use (&$observed): void {
            $observed = $event;
        });

        $subscriber = new ThreatEnforcementSubscriber($this->checker(), [], dispatcher: $dispatcher);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        self::assertInstanceOf(ThreatDecisionMatched::class, $observed);
        self::assertSame('ban', $observed->decision->type);
        self::assertFalse($event->hasResponse());
    }

    public function testAListenerResponseWinsOverTheTable(): void
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener(ThreatDecisionMatched::class, static function (ThreatDecisionMatched $event): void {
            $event->setResponse(new Response('', 418));
        });

        $subscriber = new ThreatEnforcementSubscriber($this->checker(), ['ban' => 403], dispatcher: $dispatcher);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        self::assertSame(418, self::response($event)->getStatusCode());
    }

    public function testARouteNamedInTheTableIsNeverEnforcedByEitherStage(): void
    {
        $usernameStore = new InMemoryThreatDecisionStore();
        $usernameStore->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::of('username'), 'jane.doe', 'captcha', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $networkSubscriber = new ThreatEnforcementSubscriber($this->checker(), ['captcha' => 'app_captcha']);
        $identitySubscriber = new ThreatEnforcementSubscriber($this->checker($usernameStore), ['captcha' => 'app_captcha'], tokenStorage: $tokenStorage);

        $networkEvent = $this->requestEvent('/captcha', route: 'app_captcha');
        $networkSubscriber->onNetworkStage($networkEvent);
        self::assertFalse($networkEvent->hasResponse());

        $identityEvent = $this->requestEvent('/captcha', route: 'app_captcha');
        $identitySubscriber->onIdentityStage($identityEvent);
        self::assertFalse($identityEvent->hasResponse());
    }

    public function testAnExcludedPathIsNeverEnforcedByEitherStage(): void
    {
        $usernameStore = new InMemoryThreatDecisionStore();
        $usernameStore->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::of('username'), 'jane.doe', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $networkSubscriber = new ThreatEnforcementSubscriber($this->checker(), ['ban' => 403], excludePaths: ['^/health']);
        $identitySubscriber = new ThreatEnforcementSubscriber($this->checker($usernameStore), ['ban' => 403], excludePaths: ['^/health'], tokenStorage: $tokenStorage);

        $networkEvent = $this->requestEvent('/health/ping');
        $networkSubscriber->onNetworkStage($networkEvent);
        self::assertFalse($networkEvent->hasResponse());

        $identityEvent = $this->requestEvent('/health/ping');
        $identitySubscriber->onIdentityStage($identityEvent);
        self::assertFalse($identityEvent->hasResponse());
    }

    public function testItIgnoresSubRequestsOnBothStages(): void
    {
        $subscriber = new ThreatEnforcementSubscriber($this->checker(), ['ban' => 403]);

        $networkEvent = $this->requestEvent('/orders', isMainRequest: false);
        $subscriber->onNetworkStage($networkEvent);
        self::assertFalse($networkEvent->hasResponse());

        $identityEvent = $this->requestEvent('/orders', isMainRequest: false);
        $subscriber->onIdentityStage($identityEvent);
        self::assertFalse($identityEvent->hasResponse());
    }

    public function testTheIdentityStageEnforcesAUsernameDecision(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::of('username'), 'jane.doe', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $subscriber = new ThreatEnforcementSubscriber($this->checker($store), ['ban' => 403], tokenStorage: $tokenStorage);

        $event = $this->requestEvent('/orders');
        $subscriber->onIdentityStage($event);

        self::assertSame(403, self::response($event)->getStatusCode());
    }

    public function testTheNetworkStageNeverConsultsTokenStorage(): void
    {
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('getToken');

        // Reachable through the subscriber's constructor only, never used by onNetworkStage.
        $subscriber = new ThreatEnforcementSubscriber($this->checker(), ['ban' => 403], tokenStorage: $tokenStorage);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        self::assertSame(403, self::response($event)->getStatusCode());
    }

    public function testTheNetworkStageIgnoresAUsernameScopedDecision(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::of('username'), 'jane.doe', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $subscriber = new ThreatEnforcementSubscriber($this->checker($store), ['ban' => 403]);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        self::assertFalse($event->hasResponse());
    }

    public function testTheIdentityStageIgnoresAnIpScopedDecision(): void
    {
        $subscriber = new ThreatEnforcementSubscriber($this->checker(), ['ban' => 403]);

        $event = $this->requestEvent('/orders');
        $subscriber->onIdentityStage($event);

        self::assertFalse($event->hasResponse());
    }

    public function testANetworkDecisionWinsOverAnIdentityDecisionOnTheSameRequest(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            // Lower ThreatRemediation priority than "ban" (captcha 30 vs ban 40), yet it must still
            // win: the identity stage never runs once the network stage has answered.
            new ThreatDecision('crowdsec', '1', ThreatScope::ip(), '127.0.0.1', 'captcha', new \DateTimeImmutable()),
            new ThreatDecision('crowdsec', '2', ThreatScope::of('username'), 'jane.doe', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->expects(self::never())->method('getToken');

        $urlGenerator = $this->createMock(UrlGeneratorInterface::class);
        $urlGenerator->method('generate')->with('app_captcha')->willReturn('/captcha');

        $subscriber = new ThreatEnforcementSubscriber(
            $this->checker($store),
            ['ban' => 403, 'captcha' => 'app_captcha'],
            tokenStorage: $tokenStorage,
            urlGenerator: $urlGenerator,
        );

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber($subscriber);

        $event = $this->requestEvent('/orders');
        $dispatcher->dispatch($event, KernelEvents::REQUEST);

        $response = self::response($event);
        self::assertSame(302, $response->getStatusCode());
        self::assertSame('/captcha', $response->headers->get('Location'));
    }

    public function testTheIdentityStageStillRunsWhenTheNetworkStageFoundNothing(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::of('username'), 'jane.doe', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $subscriber = new ThreatEnforcementSubscriber($this->checker($store), ['ban' => 403], tokenStorage: $tokenStorage);

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber($subscriber);

        $event = $this->requestEvent('/orders');
        $dispatcher->dispatch($event, KernelEvents::REQUEST);

        self::assertSame(403, self::response($event)->getStatusCode());
    }

    public function testCountryAndAsnHeadersAreReadWhenConfigured(): void
    {
        $store = new InMemoryThreatDecisionStore();
        $store->apply('crowdsec', [
            new ThreatDecision('crowdsec', '1', ThreatScope::country(), 'FR', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $subscriber = new ThreatEnforcementSubscriber($this->checker($store), ['ban' => 403], countryHeader: 'Cf-IPCountry');

        $event = $this->requestEvent('/orders');
        $event->getRequest()->headers->set('Cf-IPCountry', 'FR');
        $subscriber->onNetworkStage($event);

        self::assertTrue($event->hasResponse());
    }

    public function testAThrowingListenerIsLoggedAndLetsTheRequestThrough(): void
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener(ThreatDecisionMatched::class, static function (): never {
            throw new \RuntimeException('boom');
        });

        $logger = new CollectingLogger();
        $subscriber = new ThreatEnforcementSubscriber($this->checker(), ['ban' => 403], dispatcher: $dispatcher, logger: $logger);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        self::assertFalse($event->hasResponse());
        self::assertNotEmpty($logger->records);
        self::assertSame('error', $logger->records[0]['level']);
    }

    public function testAnUnknownRouteIsLoggedAndLetsTheRequestThrough(): void
    {
        $urlGenerator = $this->createMock(UrlGeneratorInterface::class);
        $urlGenerator->method('generate')->willThrowException(new RouteNotFoundException('no such route'));

        $logger = new CollectingLogger();
        $subscriber = new ThreatEnforcementSubscriber($this->checker(), ['ban' => 'app_missing'], urlGenerator: $urlGenerator, logger: $logger);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        self::assertFalse($event->hasResponse());
        self::assertNotEmpty($logger->records);
        self::assertSame('error', $logger->records[0]['level']);
    }

    public function testACheckerThatThrowsLeavesTheRequestAlone(): void
    {
        $checker = new class implements ThreatCheckerInterface {
            public function decisionsFor(ThreatSubject $subject): array
            {
                throw new \RuntimeException('store is down');
            }

            public function highestFor(ThreatSubject $subject): ?ThreatDecision
            {
                return null;
            }
        };

        $logger = new CollectingLogger();
        $subscriber = new ThreatEnforcementSubscriber($checker, ['ban' => 403], logger: $logger);

        $event = $this->requestEvent('/orders');
        $subscriber->onNetworkStage($event);

        self::assertFalse($event->hasResponse());
        self::assertNotEmpty($logger->records);
    }
}
