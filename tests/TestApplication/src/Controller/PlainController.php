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

use Symfony\Component\HttpFoundation\Response;

/**
 * Carries no #[Track]/#[Untrack] attribute; for tests exercising the
 * default (opt-in) behaviour and recorded_paths without an attribute taking
 * precedence.
 */
final class PlainController
{
    public function __invoke(): Response
    {
        return new Response('plain');
    }
}
