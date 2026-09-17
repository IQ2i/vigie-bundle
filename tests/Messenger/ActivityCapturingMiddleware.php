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

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Processor\ActivityProcessorInterface;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Middleware\MiddlewareInterface;
use Symfony\Component\Messenger\Middleware\StackInterface;

/**
 * A next-in-stack middleware that runs a processor against a probe Activity while it's next in line,
 * capturing the result. Used to observe ActivityContextMiddleware's exposed stamp from inside the
 * window handle() opens for it, the same place a real handler's recording would happen.
 */
final class ActivityCapturingMiddleware implements MiddlewareInterface
{
    public ?Activity $captured = null;

    public function __construct(
        private readonly ActivityProcessorInterface $processor,
        private readonly Activity $probe,
    ) {
    }

    public function handle(Envelope $envelope, StackInterface $stack): Envelope
    {
        $this->captured = ($this->processor)($this->probe);

        return $envelope;
    }
}
