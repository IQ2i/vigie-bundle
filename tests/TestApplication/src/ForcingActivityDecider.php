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

namespace IQ2i\VigieBundle\Tests\TestApplication;

use IQ2i\VigieBundle\Decider\ActivityDeciderInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Forces recording of "/untracked", overriding its #[Untrack] attribute;
 * ConfigurationTest asserts a decider takes precedence over the attributes.
 */
final class ForcingActivityDecider implements ActivityDeciderInterface
{
    public function decide(Request $request): ?bool
    {
        return str_starts_with($request->getPathInfo(), '/untracked') ? true : null;
    }
}
