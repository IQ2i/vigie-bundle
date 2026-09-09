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

namespace IQ2i\VigieBundle\Recorder;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\Subject;

/**
 * Applies RecordingOptions to an Activity. The sole place a raw IP address,
 * user identifier or session id is ever redacted, so it must run before an
 * activity reaches anything else: a storage, or an ActivityRecording
 * listener.
 *
 * @internal
 */
final readonly class ActivityRedactor
{
    public function __construct(
        private RecordingOptions $options,
        private Pseudonymizer $pseudonymizer,
    ) {
    }

    public function redact(Activity $activity): Activity
    {
        $activity = $activity
            ->withIpAddress($this->redactIpAddress($activity->ipAddress))
            ->withUserIdentifier($this->redactUserIdentifier($activity->userIdentifier))
            ->withUserAgent($this->options->userAgent ? $activity->userAgent : null)
            ->withUri($this->options->uri ? $activity->uri : null)
            ->withRoute($this->options->route ? $activity->route : null)
            ->withMethod($this->options->method ? $activity->method : null)
            ->withStatusCode($this->options->statusCode ? $activity->statusCode : null)
            ->withContext($this->options->context ? $activity->context : [])
            ->withFirewall($this->options->firewall ? $activity->firewall : null)
            ->withRequestId($this->options->requestId ? $activity->requestId : null)
            ->withSubject($this->redactSubject($activity->subject))
        ;

        // Never stored in the clear: a session id is a credential, no "keep raw" mode is offered.
        return $activity->withSessionId(
            $this->options->sessionId && null !== $activity->sessionId
                ? $this->pseudonymizer->hash($activity->sessionId)
                : null,
        );
    }

    private function redactIpAddress(?string $ipAddress): ?string
    {
        return null !== $ipAddress
            ? $this->options->ipAddressMode->applyToIpAddress($ipAddress, $this->pseudonymizer)
            : null;
    }

    private function redactUserIdentifier(?string $userIdentifier): ?string
    {
        return null !== $userIdentifier
            ? $this->options->userIdentifierMode->applyToUserIdentifier($userIdentifier, $this->pseudonymizer)
            : null;
    }

    // $owner is a user identifier (the resource's owner), so it goes through the exact same mode
    // and secret as Activity::$userIdentifier: a scenario can compare user.hash and
    // vigie.subject.owner for equality regardless of record.user_identifier.
    private function redactSubject(?Subject $subject): ?Subject
    {
        if (null === $subject) {
            return null;
        }

        return new Subject($subject->type, $subject->id, $this->redactUserIdentifier($subject->owner));
    }
}
