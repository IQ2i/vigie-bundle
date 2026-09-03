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
use IQ2i\VigieBundle\Processor\TokenProcessor;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class TokenProcessorTest extends TestCase
{
    public function testItIsANoOpWithoutATokenStorage(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $processor = new TokenProcessor();

        self::assertSame($activity, $processor($activity));
    }

    public function testItIsANoOpWithoutAToken(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $processor = new TokenProcessor(new TokenStorage());

        self::assertSame($activity, $processor($activity));
    }

    public function testItFillsUserIdentifierFromTheToken(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $processor = new TokenProcessor($tokenStorage);
        $processed = $processor($activity);

        self::assertSame('jane.doe', $processed->userIdentifier);
    }

    public function testItNeverOverwritesAnExplicitUserIdentifier(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable(), userIdentifier: 'john.doe');

        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken(new UsernamePasswordToken(new InMemoryUser('jane.doe', null), 'main'));

        $processor = new TokenProcessor($tokenStorage);
        $processed = $processor($activity);

        self::assertSame('john.doe', $processed->userIdentifier);
    }

    public function testItFillsImpersonatorFromASwitchUserToken(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());

        $originalToken = new UsernamePasswordToken(new InMemoryUser('admin', null), 'main');
        $switchToken = new SwitchUserToken(new InMemoryUser('jane.doe', null), 'main', ['ROLE_USER'], $originalToken);

        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken($switchToken);

        $processor = new TokenProcessor($tokenStorage);
        $processed = $processor($activity);

        self::assertSame('admin', $processed->context['impersonator']);
    }

    public function testItNeverOverwritesAnExplicitImpersonatorContextKey(): void
    {
        $activity = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable(), context: ['impersonator' => 'already-set']);

        $originalToken = new UsernamePasswordToken(new InMemoryUser('admin', null), 'main');
        $switchToken = new SwitchUserToken(new InMemoryUser('jane.doe', null), 'main', ['ROLE_USER'], $originalToken);

        $tokenStorage = new TokenStorage();
        $tokenStorage->setToken($switchToken);

        $processor = new TokenProcessor($tokenStorage);
        $processed = $processor($activity);

        self::assertSame('already-set', $processed->context['impersonator']);
    }
}
