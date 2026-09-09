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

use IQ2i\VigieBundle\Attribute\Untrack;
use Symfony\Component\HttpFoundation\Response;

/**
 * Marked #[Untrack], to exercise the full kernel.controller → kernel.response wiring end to end.
 */
#[Untrack]
final class UntrackedController
{
    public function __invoke(): Response
    {
        return new Response('untracked');
    }
}
