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

namespace IQ2i\VigieBundle\Processor;

use IQ2i\VigieBundle\Model\Activity;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;

/**
 * Fills userIdentifier from the current security token, when there is one.
 * Also fills context.impersonator from a SwitchUserToken's original token,
 * without overwriting a key already present. Never overwrites a field the
 * activity already carries. Registered only when symfony/security-core is
 * installed.
 */
final readonly class TokenProcessor implements ActivityProcessorInterface
{
    public function __construct(
        private ?TokenStorageInterface $tokenStorage = null,
    ) {
    }

    public function __invoke(Activity $activity): Activity
    {
        $token = $this->tokenStorage?->getToken();

        if (null === $token) {
            return $activity;
        }

        if (null === $activity->userIdentifier) {
            $activity = $activity->withUserIdentifier($token->getUserIdentifier());
        }

        if ($token instanceof SwitchUserToken && !\array_key_exists('impersonator', $activity->context)) {
            $activity = $activity->withAddedContext(['impersonator' => $token->getOriginalToken()->getUserIdentifier()]);
        }

        return $activity;
    }
}
