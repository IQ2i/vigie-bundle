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

namespace IQ2i\VigieBundle\Threat;

/**
 * A SIEM was unreachable, rejected the request, or answered something a
 * ThreatProviderInterface could not read as a batch of decisions.
 */
final class ThreatProviderException extends \RuntimeException
{
}
