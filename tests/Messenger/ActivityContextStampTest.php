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

use IQ2i\VigieBundle\Messenger\ActivityContextStamp;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Stamp\DelayStamp;
use Symfony\Component\Messenger\Stamp\ReceivedStamp;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;
use Symfony\Component\Messenger\Transport\Serialization\PhpSerializer;

final class ActivityContextStampTest extends TestCase
{
    public function testItSurvivesATransportRoundTrip(): void
    {
        $envelope = new Envelope(new \stdClass(), [new ActivityContextStamp(requestId: 'req-1', userIdentifier: 'jane.doe')]);

        $decoded = (new PhpSerializer())->decode((new PhpSerializer())->encode($envelope));

        $stamp = $decoded->last(ActivityContextStamp::class);
        self::assertNotNull($stamp);
        self::assertSame('req-1', $stamp->requestId);
        self::assertSame('jane.doe', $stamp->userIdentifier);
    }

    /**
     * SendFailedMessageForRetryListener::withLimitedHistory() only ever adds/rewrites DelayStamp and
     * RedeliveryStamp when scheduling a retry (see vendor/symfony/messenger); every other stamp,
     * including this one, passes through Envelope::with() untouched. This locks in that assumption
     * without depending on the listener's internals directly.
     */
    public function testItSurvivesTheStampsARetryEnvelopeAddsOnTopOfIt(): void
    {
        $envelope = new Envelope(new \stdClass(), [
            new ReceivedStamp('async'),
            new ActivityContextStamp(requestId: 'req-1', userIdentifier: 'jane.doe'),
        ]);

        $retryEnvelope = $envelope->with(new DelayStamp(1000), new RedeliveryStamp(1));

        $stamp = $retryEnvelope->last(ActivityContextStamp::class);
        self::assertNotNull($stamp);
        self::assertSame('req-1', $stamp->requestId);
        self::assertSame('jane.doe', $stamp->userIdentifier);
    }
}
