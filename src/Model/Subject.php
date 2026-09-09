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

namespace IQ2i\VigieBundle\Model;

/**
 * The target an activity was performed on: a free-form type ("user",
 * "order") chosen by the application, and an id. $owner, when known, is the
 * user identifier of whoever owns the resource, so a scenario can compare it
 * against the acting user and flag an IDOR attempt. It goes through the same
 * redaction as Activity::$userIdentifier: see ActivityRedactor.
 */
final readonly class Subject
{
    public string $id;

    public function __construct(
        public string $type,
        string|int $id,
        public ?string $owner = null,
    ) {
        $this->id = (string) $id;
    }
}
