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

use Symfony\Component\HttpFoundation\Request;

/**
 * @internal
 *
 * The firewall name a request was matched against, read from the
 * "_firewall_context" attribute SecurityBundle's FirewallMap sets on every request
 */
final class FirewallName
{
    public static function fromRequest(Request $request): ?string
    {
        $context = $request->attributes->get('_firewall_context');

        if (!\is_string($context) || '' === $context) {
            return null;
        }

        $prefix = 'security.firewall.map.context.';

        return str_starts_with($context, $prefix) ? substr($context, \strlen($prefix)) : $context;
    }
}
