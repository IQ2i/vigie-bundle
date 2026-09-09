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

use IQ2i\VigieBundle\Recorder\Pseudonymizer;
use IQ2i\VigieBundle\Recorder\QueryNormalizer;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use PHPUnit\Framework\TestCase;

final class QueryNormalizerTest extends TestCase
{
    public function testUserIdentifierIsUnchangedWhenModeIsKeep(): void
    {
        $normalizer = self::normalizer(new RecordingOptions(userIdentifier: true));

        self::assertSame('jane.doe', $normalizer->userIdentifier('jane.doe'));
    }

    public function testUserIdentifierIsUnchangedWhenModeIsDrop(): void
    {
        $normalizer = self::normalizer(new RecordingOptions(userIdentifier: false));

        self::assertSame('jane.doe', $normalizer->userIdentifier('jane.doe'));
    }

    public function testUserIdentifierIsHashedWhenModeIsHash(): void
    {
        $normalizer = self::normalizer(new RecordingOptions(userIdentifier: 'hash'));

        self::assertSame((new Pseudonymizer('test-secret'))->hash('jane.doe'), $normalizer->userIdentifier('jane.doe'));
    }

    public function testSessionIdIsAlwaysHashed(): void
    {
        $normalizer = self::normalizer(new RecordingOptions());

        self::assertSame((new Pseudonymizer('test-secret'))->hash('raw-session-id'), $normalizer->sessionId('raw-session-id'));
    }

    private static function normalizer(RecordingOptions $options): QueryNormalizer
    {
        return new QueryNormalizer($options, new Pseudonymizer('test-secret'));
    }
}
