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
 * @internal what actually decided whether the current request gets
 * recorded — surfaced by the profiler panel, see VigieDataCollector
 */
enum TrackingSource
{
    case Decider;
    case Attribute;
    case IgnoredPath;
    case RecordedPath;
    case Default;
    case NotMainRequest;
    case HttpDisabled;
}
