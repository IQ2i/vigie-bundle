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

namespace IQ2i\VigieBundle\Decider;

use Symfony\Component\HttpFoundation\Request;

/**
 * Decides, from the request alone, whether an HTTP activity should be
 * recorded — for cases the static #[Track]/#[Untrack] attributes can't
 * express (e.g. filtering a single controller on its query string).
 *
 * Any implementing service is automatically tagged and consulted, in
 * priority order, before the attributes and before http.*_paths — the first non-null verdict wins.
 */
interface ActivityDeciderInterface
{
    /**
     * @return bool|null true to record, false to ignore, null to abstain
     *                   and let the next decider (or the attributes, or
     *                   the path filters, or the opt-in default) decide
     */
    public function decide(Request $request): ?bool;
}
