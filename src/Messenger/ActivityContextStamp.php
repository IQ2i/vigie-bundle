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

use Symfony\Component\Messenger\Stamp\StampInterface;

/**
 * Carries the dispatching request's id and acting user onto a Messenger envelope, so a handler running
 * later (in a worker, with no request of its own) can still be correlated with the request that
 * triggered it. No IP: see ActivityContextMiddleware and doc/recording.md#recording-from-a-worker for
 * why.
 *
 * Carries the *raw* userIdentifier: this stamp is not redacted, `record.*` still applies at record
 * time, the same as everywhere else. See doc/recording.md.
 */
final readonly class ActivityContextStamp implements StampInterface
{
    public function __construct(
        public ?string $requestId = null,
        public ?string $userIdentifier = null,
    ) {
    }
}
