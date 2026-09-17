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

namespace IQ2i\VigieBundle\Messenger;

use IQ2i\VigieBundle\Http\RequestContext;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Processor\ActivityProcessorInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Middleware\MiddlewareInterface;
use Symfony\Component\Messenger\Middleware\StackInterface;
use Symfony\Component\Messenger\Stamp\ReceivedStamp;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Dispatch side (no ReceivedStamp yet): stamps the envelope with the current main request's id and
 * acting user, when there is one and it isn't stamped already. Worker side (ReceivedStamp present):
 * exposes that stamp to ActivityRecorder's processors for the duration of handle(), on the model of
 * RequestContextProcessor/TokenProcessor — fill a field only if the activity doesn't already carry it,
 * never overwrite.
 *
 * No IP on the stamp: it ages badly across retries (the client may be long gone by the time a message
 * is retried) and would duplicate a piece of personal data into the transport for no operational gain
 * — a session/user identifier is enough to act on the account, which is what this correlation is for.
 * See doc/recording.md#recording-from-a-worker.
 */
final class ActivityContextMiddleware implements MiddlewareInterface, ActivityProcessorInterface, ResetInterface
{
    private ?ActivityContextStamp $stamp = null;

    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly ?TokenStorageInterface $tokenStorage = null,
    ) {
    }

    public function handle(Envelope $envelope, StackInterface $stack): Envelope
    {
        // Worker side: a received envelope re-enters the same bus, and its middleware stack, from
        // Worker::handleMessage(). Expose the stamp for the whole nested handle() call, which is where
        // the actual handler (and anything it records) runs.
        if (null !== $envelope->last(ReceivedStamp::class)) {
            $this->stamp = $envelope->last(ActivityContextStamp::class);

            try {
                return $stack->next()->handle($envelope, $stack);
            } finally {
                $this->stamp = null;
            }
        }

        // Dispatch side. Never overwrite a stamp already present (e.g. re-dispatched by application
        // code), and never stamp a message with no request to correlate to (a CLI command, a worker
        // dispatching a message of its own).
        if (null !== $envelope->last(ActivityContextStamp::class)) {
            return $stack->next()->handle($envelope, $stack);
        }

        $request = $this->requestStack->getMainRequest();

        if (null === $request) {
            return $stack->next()->handle($envelope, $stack);
        }

        $envelope = $envelope->with(new ActivityContextStamp(
            requestId: RequestContext::requestId($request),
            userIdentifier: $this->tokenStorage?->getToken()?->getUserIdentifier(),
        ));

        return $stack->next()->handle($envelope, $stack);
    }

    public function __invoke(Activity $activity): Activity
    {
        if (null === $this->stamp) {
            return $activity;
        }

        if (null === $activity->requestId && null !== $this->stamp->requestId) {
            $activity = $activity->withRequestId($this->stamp->requestId);
        }

        if (null === $activity->userIdentifier && null !== $this->stamp->userIdentifier) {
            $activity = $activity->withUserIdentifier($this->stamp->userIdentifier);
        }

        return $activity;
    }

    /**
     * Safety net for a worker runtime: a handler throwing past the try/finally above already clears
     * the stamp, this only guards against something stranger leaving it set.
     */
    public function reset(): void
    {
        $this->stamp = null;
    }
}
