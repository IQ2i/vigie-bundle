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
 * A dependency-free route for tests that just need something to send a request through; marked #[Track].
 */
#[Track]
final class PingController
{
    public function __invoke(): Response
    {
        return new Response('pong');
    }
}
