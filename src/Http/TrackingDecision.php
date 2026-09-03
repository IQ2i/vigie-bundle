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

/**
 * @internal why HttpActivitySubscriber did or didn't record the current
 * request — stamped on the "_vigie_decision" request attribute, read back
 * by VigieDataCollector
 */
final readonly class TrackingDecision
{
    public const ATTRIBUTE = '_vigie_decision';

    public function __construct(
        public bool $recorded,
        public TrackingSource $source,
        public ?string $detail = null,
    ) {
    }
}
