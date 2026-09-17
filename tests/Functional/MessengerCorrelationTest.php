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

namespace IQ2i\VigieBundle\Tests\Functional;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Processor\RequestContextProcessor;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\ReceivedStamp;
use Symfony\Component\Messenger\Transport\InMemory\InMemoryTransport;

/**
 * Simulates, without a real worker process, exactly what Worker::handleMessage() does: fetch one
 * envelope off the transport, stamp it with ReceivedStamp, and re-dispatch it into the same bus. See
 * doc/recording.md#recording-from-a-worker.
 */
final class MessengerCorrelationTest extends FunctionalTestCase
{
    public function testAnActivityRecordedInAHandlerCarriesTheDispatchingRequestId(): void
    {
        $client = self::createClient(['environment' => 'messenger']);
        $client->request('GET', '/messenger-dispatch');
        self::assertResponseIsSuccessful();

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        $httpActivity = self::first($storage->all(), static fn (Activity $a): bool => 'http_request' === $a->type->value);
        self::assertNotNull($httpActivity);
        self::assertNotNull($httpActivity->requestId);

        $this->consumeOneMessage();

        $jobActivity = self::first($storage->all(), static fn (Activity $a): bool => 'job.done' === $a->action);
        self::assertNotNull($jobActivity);
        self::assertSame($httpActivity->requestId, $jobActivity->requestId);
    }

    public function testTheStampIsGoneOnceTheHandlerReturns(): void
    {
        $client = self::createClient(['environment' => 'messenger']);
        $client->request('GET', '/messenger-dispatch');
        self::assertResponseIsSuccessful();

        $this->consumeOneMessage();

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $countAfterFirstJob = \count($storage->all());

        // A worker is a separate PHP process: no kernel.request ever fires there, so
        // RequestContextProcessor never remembers a request either. Reset it to simulate that, the
        // same safety net RequestContextProcessor documents for its own worker-runtime case.
        /** @var RequestContextProcessor $requestContextProcessor */
        $requestContextProcessor = self::getContainer()->get(RequestContextProcessor::class);
        $requestContextProcessor->reset();

        // A second activity recorded outside any handle() window (here: directly, as a plain worker
        // job would with no message of its own to correlate) must not pick up a stamp left over from
        // the job above.
        /** @var ActivityRecorderInterface $recorder */
        $recorder = self::getContainer()->get(ActivityRecorderInterface::class);
        $recorder->custom('outside.any.handler');

        $activities = $storage->all();
        self::assertCount($countAfterFirstJob + 1, $activities);
        self::assertNull($activities[$countAfterFirstJob]->requestId);
    }

    private function consumeOneMessage(): void
    {
        /** @var InMemoryTransport $transport */
        $transport = self::getContainer()->get('messenger.transport.async');
        /** @var MessageBusInterface $bus */
        $bus = self::getContainer()->get(MessageBusInterface::class);

        $envelope = null;

        foreach ($transport->get() as $envelope) {
            break;
        }

        self::assertNotNull($envelope, 'Expected one message queued on the "async" transport.');

        $bus->dispatch($envelope->with(new ReceivedStamp('async')));
        $transport->ack($envelope);
    }

    /**
     * @param list<Activity>           $activities
     * @param \Closure(Activity): bool $matches
     */
    private static function first(array $activities, \Closure $matches): ?Activity
    {
        foreach ($activities as $activity) {
            if ($matches($activity)) {
                return $activity;
            }
        }

        return null;
    }
}
