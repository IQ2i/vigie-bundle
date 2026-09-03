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
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Minimal endpoints for SecurityFlowTest to authenticate against; just
 * enough to exercise LoginSuccessEvent/LoginFailureEvent/SwitchUserEvent
 * through a real HTTP request/response cycle, not a mocked one.
 */
final readonly class SecurityController
{
    public function __construct(
        private Security $security,
    ) {
    }

    #[Track]
    public function protectedAction(): JsonResponse
    {
        return new JsonResponse(['user' => $this->security->getUser()?->getUserIdentifier()]);
    }
}
