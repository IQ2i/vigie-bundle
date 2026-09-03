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

use IQ2i\VigieBundle\EventSubscriber\SecurityActivitySubscriber;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;
use Symfony\Component\Security\Http\Event\TokenDeauthenticatedEvent;

final class SecurityActivitySubscriberTest extends TestCase
{
    private ActivityRecorderInterface&\PHPUnit\Framework\MockObject\MockObject $recorder;
    private SecurityActivitySubscriber $subscriber;

    protected function setUp(): void
    {
        $this->recorder = $this->createMock(ActivityRecorderInterface::class);
        $this->subscriber = new SecurityActivitySubscriber($this->recorder, new MockClock());
    }

    private function passport(string $userIdentifier): Passport
    {
        return new Passport(
            new UserBadge($userIdentifier, static fn (): InMemoryUser => new InMemoryUser($userIdentifier, null)),
            $this->createMock(CredentialsInterface::class),
        );
    }

    public function testLoginSuccess(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame(ActivityType::LoginSuccess, $activity->type);
                self::assertSame('jane.doe', $activity->userIdentifier);
                self::assertSame('main', $activity->firewall);

                return true;
            }));

        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $token = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');

        $event = new LoginSuccessEvent(
            $authenticator,
            $this->passport('jane.doe'),
            $token,
            Request::create('/login'),
            null,
            'main',
        );

        $this->subscriber->onLoginSuccess($event);
    }

    public function testLoginSuccessRecordsTheAuthenticatorAndWhetherItIsInteractive(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('InteractiveStubAuthenticator', $activity->context['authenticator']);
                self::assertTrue($activity->context['interactive']);

                return true;
            }));

        $authenticator = new InteractiveStubAuthenticator();
        $token = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');

        $event = new LoginSuccessEvent($authenticator, $this->passport('jane.doe'), $token, Request::create('/login'), null, 'main');

        $this->subscriber->onLoginSuccess($event);
    }

    public function testANonInteractiveAuthenticatorIsRecordedAsSuch(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertFalse($activity->context['interactive']);

                return true;
            }));

        // A mocked AuthenticatorInterface doesn't implement
        // InteractiveAuthenticatorInterface at all; the same shape as a
        // stateless API token authenticator.
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $token = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');

        $event = new LoginSuccessEvent($authenticator, $this->passport('jane.doe'), $token, Request::create('/login'), null, 'main');

        $this->subscriber->onLoginSuccess($event);
    }

    public function testRecordNonInteractiveFalseSkipsNonInteractiveLogins(): void
    {
        $this->recorder->expects(self::never())->method('record');

        $subscriber = new SecurityActivitySubscriber($this->recorder, new MockClock(), recordNonInteractive: false);

        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $token = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');

        $event = new LoginSuccessEvent($authenticator, $this->passport('jane.doe'), $token, Request::create('/login'), null, 'main');

        $subscriber->onLoginSuccess($event);
    }

    public function testRecordNonInteractiveFalseStillRecordsInteractiveLogins(): void
    {
        $this->recorder->expects(self::once())->method('record');

        $subscriber = new SecurityActivitySubscriber($this->recorder, new MockClock(), recordNonInteractive: false);

        $authenticator = new InteractiveStubAuthenticator();
        $token = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');

        $event = new LoginSuccessEvent($authenticator, $this->passport('jane.doe'), $token, Request::create('/login'), null, 'main');

        $subscriber->onLoginSuccess($event);
    }

    /**
     * @return iterable<string, array{AuthenticationException, string, bool}>
     */
    public static function loginFailureExceptionProvider(): iterable
    {
        yield 'bad credentials' => [new BadCredentialsException(), 'BadCredentialsException', false];
        yield 'throttled' => [new TooManyLoginAttemptsAuthenticationException(60), 'TooManyLoginAttemptsAuthenticationException', true];
    }

    #[DataProvider('loginFailureExceptionProvider')]
    public function testLoginFailure(AuthenticationException $exception, string $expectedExceptionClass, bool $expectedThrottled): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity) use ($expectedExceptionClass, $expectedThrottled): bool {
                self::assertSame(ActivityType::LoginFailure, $activity->type);
                self::assertSame('jane.doe', $activity->userIdentifier);
                self::assertArrayHasKey('reason', $activity->context);
                self::assertSame($expectedExceptionClass, $activity->context['exception']);
                self::assertSame($expectedThrottled, $activity->context['throttled']);
                self::assertSame('main', $activity->firewall);

                return true;
            }));

        $authenticator = $this->createMock(AuthenticatorInterface::class);

        $event = new LoginFailureEvent(
            $exception,
            $authenticator,
            Request::create('/login'),
            null,
            'main',
            $this->passport('jane.doe'),
        );

        $this->subscriber->onLoginFailure($event);
    }

    public function testLoginFailureFallsBackToTheExceptionsUserIdentifierWithoutAPassport(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame('jane.doe', $activity->userIdentifier);

                return true;
            }));

        $exception = new UserNotFoundException();
        $exception->setUserIdentifier('jane.doe');

        $event = new LoginFailureEvent(
            $exception,
            $this->createMock(AuthenticatorInterface::class),
            Request::create('/login'),
            null,
            'main',
            null,
        );

        $this->subscriber->onLoginFailure($event);
    }

    public function testLogout(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame(ActivityType::Logout, $activity->type);
                self::assertSame('jane.doe', $activity->userIdentifier);
                self::assertSame('main', $activity->firewall);

                return true;
            }));

        $token = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');

        $request = Request::create('/logout');
        $request->attributes->set('_firewall_context', 'security.firewall.map.context.main');

        $event = new LogoutEvent($request, $token);

        $this->subscriber->onLogout($event);
    }

    public function testSwitchUser(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame(ActivityType::SwitchUser, $activity->type);
                self::assertSame('john.doe', $activity->userIdentifier);
                self::assertSame('enter', $activity->context['direction']);
                self::assertSame('jane.doe', $activity->context['original_user']);

                return true;
            }));

        $originalToken = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');
        $targetUser = new InMemoryUser('john.doe', null);
        // SwitchUserListener wraps the impersonator's own token into a
        // SwitchUserToken; a bare token here would be the "exiting
        // impersonation" case, not "entering" it.
        $switchToken = new SwitchUserToken($targetUser, 'main', ['ROLE_USER'], $originalToken);

        $event = new SwitchUserEvent(Request::create('/'), $targetUser, $switchToken);

        $this->subscriber->onSwitchUser($event);
    }

    public function testSwitchUserExitDoesNotReportAnOriginalUser(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame(ActivityType::SwitchUser, $activity->type);
                self::assertSame('jane.doe', $activity->userIdentifier);
                self::assertSame('exit', $activity->context['direction']);
                self::assertNull($activity->context['original_user']);

                return true;
            }));

        // Exiting impersonation: the event carries the restored original
        // token directly, not a SwitchUserToken; there is no impersonator
        // to report once back to one's own identity.
        $restoredToken = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');

        $event = new SwitchUserEvent(Request::create('/'), new InMemoryUser('jane.doe', null), $restoredToken);

        $this->subscriber->onSwitchUser($event);
    }

    public function testTokenDeauthenticated(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame(ActivityType::TokenDeauthenticated, $activity->type);
                self::assertSame('jane.doe', $activity->userIdentifier);

                return true;
            }));

        $originalToken = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');
        $event = new TokenDeauthenticatedEvent($originalToken, Request::create('/'));

        $this->subscriber->onTokenDeauthenticated($event);
    }

    public function testAccessDeniedIsRecordedForAnAuthenticatedToken(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame(ActivityType::AccessDenied, $activity->type);
                self::assertSame('ROLE_ADMIN,ROLE_SUPER_ADMIN', $activity->context['attributes']);
                self::assertSame('IQ2i\VigieBundle\Tests\EventSubscriber\AccessDeniedSubjectStub', $activity->context['subject_type']);

                return true;
            }));

        $exception = new AccessDeniedException();
        $exception->setAttributes(['ROLE_ADMIN', 'ROLE_SUPER_ADMIN']);
        $exception->setSubject(new AccessDeniedSubjectStub());

        $subscriber = $this->subscriberWithTokenStorage($this->authenticatedTokenStorage());

        $subscriber->onKernelException($this->exceptionEvent($exception));
    }

    public function testAccessDeniedIsIgnoredForAnAnonymousToken(): void
    {
        $this->recorder->expects(self::never())->method('record');

        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(new NullToken());

        $subscriber = $this->subscriberWithTokenStorage($tokenStorage);

        $subscriber->onKernelException($this->exceptionEvent(new AccessDeniedException()));
    }

    public function testAccessDeniedIsIgnoredWithoutATokenStorage(): void
    {
        $this->recorder->expects(self::never())->method('record');

        $this->subscriber->onKernelException($this->exceptionEvent(new AccessDeniedException()));
    }

    public function testAccessDeniedIsIgnoredOnASubRequest(): void
    {
        $this->recorder->expects(self::never())->method('record');

        $subscriber = $this->subscriberWithTokenStorage($this->authenticatedTokenStorage());

        $subscriber->onKernelException($this->exceptionEvent(new AccessDeniedException(), mainRequest: false));
    }

    public function testAnAccessDeniedHttpExceptionThrownDirectlyIsCaptured(): void
    {
        $this->recorder->expects(self::once())
            ->method('record')
            ->with(self::callback(static function (Activity $activity): bool {
                self::assertSame(ActivityType::AccessDenied, $activity->type);
                self::assertArrayNotHasKey('attributes', $activity->context);

                return true;
            }));

        $subscriber = $this->subscriberWithTokenStorage($this->authenticatedTokenStorage());

        $subscriber->onKernelException($this->exceptionEvent(new AccessDeniedHttpException()));
    }

    public function testAnAccessDeniedExceptionNestedInsideAnotherExceptionIsCaptured(): void
    {
        $this->recorder->expects(self::once())->method('record');

        $subscriber = $this->subscriberWithTokenStorage($this->authenticatedTokenStorage());

        $subscriber->onKernelException($this->exceptionEvent(new \RuntimeException('wrapped', previous: new AccessDeniedException())));
    }

    public function testRecordAccessDeniedFalseSkipsCapture(): void
    {
        $this->recorder->expects(self::never())->method('record');

        $subscriber = new SecurityActivitySubscriber($this->recorder, new MockClock(), $this->authenticatedTokenStorage(), recordAccessDenied: false);

        $subscriber->onKernelException($this->exceptionEvent(new AccessDeniedException()));
    }

    private function authenticatedTokenStorage(): TokenStorageInterface
    {
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        return $tokenStorage;
    }

    private function subscriberWithTokenStorage(TokenStorageInterface $tokenStorage): SecurityActivitySubscriber
    {
        return new SecurityActivitySubscriber($this->recorder, new MockClock(), $tokenStorage);
    }

    private function exceptionEvent(\Throwable $exception, bool $mainRequest = true): ExceptionEvent
    {
        return new ExceptionEvent(
            $this->createMock(HttpKernelInterface::class),
            Request::create('/admin'),
            $mainRequest ? HttpKernelInterface::MAIN_REQUEST : HttpKernelInterface::SUB_REQUEST,
            $exception,
        );
    }

    public function testARecorderFailureIsLoggedAndDoesNotBlockASuccessfulLogin(): void
    {
        $this->recorder->method('record')->willThrowException(new \RuntimeException('boom'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error');

        $subscriber = new SecurityActivitySubscriber($this->recorder, new MockClock(), logger: $logger);

        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $token = new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main');

        $event = new LoginSuccessEvent(
            $authenticator,
            $this->passport('jane.doe'),
            $token,
            Request::create('/login'),
            null,
            'main',
        );

        $subscriber->onLoginSuccess($event);
    }
}

/**
 * A minimal authenticator implementing InteractiveAuthenticatorInterface, standing in for AbstractLoginFormAuthenticator et al.
 */
final class InteractiveStubAuthenticator implements AuthenticatorInterface, InteractiveAuthenticatorInterface
{
    public function supports(Request $request): ?bool
    {
        return true;
    }

    public function authenticate(Request $request): Passport
    {
        throw new \LogicException('Not used in tests.');
    }

    public function createToken(Passport $passport, string $firewallName): \Symfony\Component\Security\Core\Authentication\Token\TokenInterface
    {
        throw new \LogicException('Not used in tests.');
    }

    public function onAuthenticationSuccess(Request $request, \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token, string $firewallName): ?\Symfony\Component\HttpFoundation\Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?\Symfony\Component\HttpFoundation\Response
    {
        return null;
    }

    public function isInteractive(): bool
    {
        return true;
    }
}

/**
 * Stands in for the entity a voter denied access to — any object works,
 * only its class name (via get_debug_type()) ends up in context.subject_type.
 */
final class AccessDeniedSubjectStub
{
}
