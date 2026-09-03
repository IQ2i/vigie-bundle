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
use Symfony\Component\HttpFoundation\Response;

/**
 * A route with no dependencies of its own, for tests that just need
 * something to send an HTTP request through; e.g. StorageFailureTest.
 * Marked #[Track] since several environments rely on it being recorded
 * without configuring recorded_paths.
 */
#[Track]
final class PingController
{
    public function __invoke(): Response
    {
        return new Response('pong');
    }
}
