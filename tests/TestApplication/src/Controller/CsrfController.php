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

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Calls isTokenValid() directly, since symfony/form isn't installed in this test application.
 */
final readonly class CsrfController
{
    public function __construct(
        private CsrfTokenManagerInterface $tokenManager,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $valid = $this->tokenManager->isTokenValid(new CsrfToken('authenticate', (string) $request->request->get('token')));

        return new JsonResponse(['valid' => $valid]);
    }
}
