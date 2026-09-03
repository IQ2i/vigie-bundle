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

namespace IQ2i\VigieBundle\Recorder;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Model\Subject;

interface ActivityRecorderInterface
{
    public function record(Activity $activity): void;

    /**
     * Records a business-defined activity in one line — occurredAt and
     * whatever the registered processors can find (userIdentifier, ipAddress,
     * userAgent, session id, request id, firewall) are filled in for you. For
     * anything else, build an Activity yourself and call record() instead.
     *
     * @param array<string, scalar|null> $context
     */
    public function custom(string $action, array $context = [], ?Subject $subject = null): void;

    /**
     * Records a security event only the application knows about — a
     * password change, a role change. Same model as custom(): occurredAt and
     * whatever the registered processors can find are filled in for you.
     *
     * @param array<string, scalar|null> $context
     *
     * @throws \InvalidArgumentException if $type is Custom or HttpRequest —
     *                                   use custom() or record() instead
     */
    public function security(ActivityType $type, ?string $userIdentifier = null, array $context = [], ?Subject $subject = null): void;
}
