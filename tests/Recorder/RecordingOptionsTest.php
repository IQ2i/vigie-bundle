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

namespace IQ2i\VigieBundle\Tests\Recorder;

use IQ2i\VigieBundle\Recorder\RecordingOptions;
use IQ2i\VigieBundle\Recorder\RecordMode;
use PHPUnit\Framework\TestCase;

final class RecordingOptionsTest extends TestCase
{
    public function testIpAddressResolvesToKeepDropOrAnonymize(): void
    {
        self::assertSame(RecordMode::Keep, (new RecordingOptions(ipAddress: true))->ipAddressMode);
        self::assertSame(RecordMode::Drop, (new RecordingOptions(ipAddress: false))->ipAddressMode);
        self::assertSame(RecordMode::Anonymize, (new RecordingOptions(ipAddress: 'anonymize'))->ipAddressMode);
    }

    public function testUserIdentifierResolvesToKeepDropOrHash(): void
    {
        self::assertSame(RecordMode::Keep, (new RecordingOptions(userIdentifier: true))->userIdentifierMode);
        self::assertSame(RecordMode::Drop, (new RecordingOptions(userIdentifier: false))->userIdentifierMode);
        self::assertSame(RecordMode::Hash, (new RecordingOptions(userIdentifier: 'hash'))->userIdentifierMode);
    }

    public function testDefaultsToKeepingEveryFieldExceptIpAddressWhichIsAnonymizedByDefault(): void
    {
        $options = new RecordingOptions();

        self::assertSame(RecordMode::Anonymize, $options->ipAddressMode);
        self::assertSame(RecordMode::Keep, $options->userIdentifierMode);
        self::assertTrue($options->userAgent);
        self::assertTrue($options->uri);
        self::assertTrue($options->route);
        self::assertTrue($options->method);
        self::assertTrue($options->statusCode);
        self::assertTrue($options->context);
        self::assertTrue($options->firewall);
        self::assertTrue($options->sessionId);
        self::assertTrue($options->requestId);
    }
}
