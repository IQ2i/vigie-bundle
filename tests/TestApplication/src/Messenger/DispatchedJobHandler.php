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

namespace IQ2i\VigieBundle\Tests\TestApplication\Messenger;

use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;

/**
 * Records an activity from inside a worker, exactly like a controller would from inside a request:
 * the correlation to the dispatching request is entirely ActivityContextMiddleware's job.
 */
final class DispatchedJobHandler
{
    public function __construct(
        private readonly ActivityRecorderInterface $recorder,
    ) {
    }

    public function __invoke(DispatchedJob $job): void
    {
        $this->recorder->custom('job.done');
    }
}
