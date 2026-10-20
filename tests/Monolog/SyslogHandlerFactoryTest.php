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

namespace IQ2i\VigieBundle\Tests\Monolog;

use IQ2i\VigieBundle\Monolog\EcsFormatter;
use IQ2i\VigieBundle\Monolog\SyslogHandlerFactory;
use Monolog\Handler\NullHandler;
use Monolog\Handler\SyslogHandler;
use Monolog\Handler\SyslogUdpHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SyslogHandlerFactoryTest extends TestCase
{
    /**
     * @return iterable<string, array{bool|string}>
     */
    public static function disabledValues(): iterable
    {
        yield 'false' => [false];
        yield 'env "0"' => ['0'];
        yield 'env "false"' => ['false'];
        yield 'env ""' => [''];
    }

    #[DataProvider('disabledValues')]
    public function testItIsANullHandlerWhenDisabled(bool|string $enabled): void
    {
        $handler = SyslogHandlerFactory::create($enabled, '127.0.0.1', 514, 'local0', 'vigie', 8192, new EcsFormatter(false));

        self::assertInstanceOf(NullHandler::class, $handler);
    }

    public function testItNeverTouchesTheSocketExtensionWhenDisabled(): void
    {
        // A host that would fail to resolve proves nothing is instantiated, since ext-sockets may be absent.
        $handler = SyslogHandlerFactory::create(false, 'no-such-host.invalid', 514, 'local0', 'vigie', 8192, new EcsFormatter(false));

        self::assertInstanceOf(NullHandler::class, $handler);
    }

    #[DataProvider('hostlessValues')]
    public function testItWritesToTheLocalSyslogWithoutAHost(?string $host): void
    {
        $handler = SyslogHandlerFactory::create('1', $host, 514, 'local0', 'vigie', 8192, $formatter = new EcsFormatter(false));

        self::assertInstanceOf(SyslogHandler::class, $handler);
        self::assertSame($formatter, $handler->getFormatter());
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function hostlessValues(): iterable
    {
        yield 'null' => [null];
        yield 'empty' => [''];
    }

    public function testItRejectsANonPositivePortOrLengthOnceEnabled(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('must be positive');

        SyslogHandlerFactory::create(true, '127.0.0.1', 0, 'local0', 'vigie', 8192, new EcsFormatter(false));
    }

    public function testItSendsUdpWithAHost(): void
    {
        if (!\extension_loaded('sockets')) {
            self::markTestSkipped('ext-sockets is required by SyslogUdpHandler.');
        }

        $handler = SyslogHandlerFactory::create(true, '127.0.0.1', '5514', 'local0', 'vigie', '4096', $formatter = new EcsFormatter(false));

        self::assertInstanceOf(SyslogUdpHandler::class, $handler);
        self::assertSame($formatter, $handler->getFormatter());
    }
}
