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
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * Nested under /protected so the "security" environment's
 * http.recorded_paths already covers it; #[IsGranted] denies any
 * authenticated user here, none of whom holds ROLE_ADMIN.
 */
final class ForbiddenController
{
    #[IsGranted('ROLE_ADMIN')]
    public function __invoke(): Response
    {
        throw new \LogicException('Never reached: #[IsGranted] denies access before the controller runs.');
    }
}
