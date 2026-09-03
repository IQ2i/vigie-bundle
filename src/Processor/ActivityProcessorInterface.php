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

/**
 * Runs, on the model of Monolog\Processor\ProcessorInterface, for every
 * activity passing through ActivityRecorder — before redaction, so whatever
 * a processor fills in is still subject to record.* like everything else.
 *
 * Tag a service with `vigie.activity_processor` (an optional `priority`
 * attribute controls order — higher runs first) to register one; it is
 * autoconfigured onto any service implementing this interface.
 */
interface ActivityProcessorInterface
{
    public function __invoke(Activity $activity): Activity;
}
