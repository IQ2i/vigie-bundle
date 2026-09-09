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

namespace IQ2i\VigieBundle\Tests\TestApplication\Controller;

use IQ2i\VigieBundle\Attribute\Track;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Exercises ActivityRecorderInterface::custom() from within a request.
 */
#[Track]
final class CustomActivityController
{
    public function __construct(
        private readonly ActivityRecorderInterface $recorder,
    ) {
    }

    public function __invoke(): Response
    {
        $this->recorder->custom('ping.hit');

        return new Response('pong');
    }
}
