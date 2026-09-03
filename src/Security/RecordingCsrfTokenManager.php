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

namespace IQ2i\VigieBundle\Security;

use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Decorates security.csrf.token_manager to record a csrf_failure on a false
 * isTokenValid() — any call site, not just the login form, since the
 * decoration is on the interface.
 */
final readonly class RecordingCsrfTokenManager implements CsrfTokenManagerInterface
{
    public function __construct(
        private CsrfTokenManagerInterface $inner,
        private ActivityRecorderInterface $recorder,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function getToken(string $tokenId): CsrfToken
    {
        return $this->inner->getToken($tokenId);
    }

    public function refreshToken(string $tokenId): CsrfToken
    {
        return $this->inner->refreshToken($tokenId);
    }

    public function removeToken(string $tokenId): ?string
    {
        return $this->inner->removeToken($tokenId);
    }

    public function isTokenValid(CsrfToken $token): bool
    {
        $valid = $this->inner->isTokenValid($token);

        if (!$valid) {
            try {
                $this->recorder->security(ActivityType::CsrfFailure, context: ['token_id' => $token->getId()]);
            } catch (\Throwable $e) {
                $this->logger?->error('Vigie could not build the "csrf_failure" activity: {message}', [
                    'message' => $e->getMessage(),
                    'exception' => $e,
                ]);
            }
        }

        return $valid;
    }
}
