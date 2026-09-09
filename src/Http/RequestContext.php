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

namespace IQ2i\VigieBundle\Http;

use IQ2i\VigieBundle\EventSubscriber\RequestIdSubscriber;
use Symfony\Component\HttpFoundation\Request;

/**
 * @internal
 */
final class RequestContext
{
    public static function sessionId(Request $request): ?string
    {
        return $request->hasSession(true) && $request->getSession()->isStarted()
            ? $request->getSession()->getId()
            : null;
    }

    public static function requestId(Request $request): ?string
    {
        $id = $request->attributes->get(RequestIdSubscriber::ATTRIBUTE);

        return \is_string($id) ? $id : null;
    }
}
