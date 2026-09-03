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

namespace IQ2i\VigieBundle\Tests\Security;

use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use IQ2i\VigieBundle\Security\RecordingCsrfTokenManager;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class RecordingCsrfTokenManagerTest extends TestCase
{
    public function testAnInvalidTokenRecordsACsrfFailure(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::once())
            ->method('security')
            ->with(ActivityType::CsrfFailure, null, ['token_id' => 'authenticate'], null);

        $manager = new RecordingCsrfTokenManager(new StaticCsrfTokenManager(false), $recorder);

        self::assertFalse($manager->isTokenValid(new CsrfToken('authenticate', 'wrong')));
    }

    public function testAValidTokenRecordsNothing(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->expects(self::never())->method('security');

        $manager = new RecordingCsrfTokenManager(new StaticCsrfTokenManager(true), $recorder);

        self::assertTrue($manager->isTokenValid(new CsrfToken('authenticate', 'right')));
    }

    public function testARecorderFailureIsLoggedAndDoesNotChangeTheReturnedValue(): void
    {
        $recorder = $this->createMock(ActivityRecorderInterface::class);
        $recorder->method('security')->willThrowException(new \RuntimeException('boom'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error');

        $manager = new RecordingCsrfTokenManager(new StaticCsrfTokenManager(false), $recorder, $logger);

        self::assertFalse($manager->isTokenValid(new CsrfToken('authenticate', 'wrong')));
    }

    public function testGetTokenRefreshTokenAndRemoveTokenDelegateToTheInnerManager(): void
    {
        $inner = new StaticCsrfTokenManager(true);
        $manager = new RecordingCsrfTokenManager($inner, $this->createMock(ActivityRecorderInterface::class));

        self::assertEquals(new CsrfToken('authenticate', 'a-value'), $manager->getToken('authenticate'));
        self::assertEquals(new CsrfToken('authenticate', 'a-refreshed-value'), $manager->refreshToken('authenticate'));
        self::assertSame('a-refreshed-value', $manager->removeToken('authenticate'));
        self::assertNull($manager->removeToken('authenticate'));
    }
}

/**
 * A CsrfTokenManagerInterface stub whose methods return a recognizable, stable value.
 */
final class StaticCsrfTokenManager implements CsrfTokenManagerInterface
{
    private ?string $value = 'a-value';

    public function __construct(
        private bool $valid,
    ) {
    }

    public function getToken(string $tokenId): CsrfToken
    {
        return new CsrfToken($tokenId, $this->value ?? 'a-value');
    }

    public function refreshToken(string $tokenId): CsrfToken
    {
        $this->value = 'a-refreshed-value';

        return new CsrfToken($tokenId, $this->value);
    }

    public function removeToken(string $tokenId): ?string
    {
        $removed = $this->value;
        $this->value = null;

        return $removed;
    }

    public function isTokenValid(CsrfToken $token): bool
    {
        return $this->valid;
    }
}
