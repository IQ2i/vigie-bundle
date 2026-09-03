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

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Processor\ActivityProcessorInterface;

/**
 * An application-defined processor, exercising the extension point
 * doc/recording.md documents; adds context.tenant to every
 * activity, alongside the bundle's own RequestContextProcessor/TokenProcessor.
 */
final class TenantProcessor implements ActivityProcessorInterface
{
    public function __invoke(Activity $activity): Activity
    {
        return $activity->withAddedContext(['tenant' => 'acme']);
    }
}
