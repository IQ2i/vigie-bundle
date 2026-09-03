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

/**
 * Always throws; exercises RequestContextProcessor's "exception_class"
 * context key on a 4xx/5xx response (see RequestContextTest).
 */
#[Track]
final class FailingController
{
    public function __invoke(): never
    {
        throw new \RuntimeException('deliberately broken');
    }
}
