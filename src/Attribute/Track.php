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

namespace IQ2i\VigieBundle\Attribute;

/**
 * Marks a controller class or action as recorded, regardless of
 * http.ignored_paths/http.recorded_paths — an attribute on a method takes
 * precedence over one on its class. The main way to opt a controller into
 * recording, since nothing is recorded by default. See doc/recording.md.
 *
 * $action overrides the recorded action label; a class-level and a
 * method-level $action combine, joined by a ".". $subject names the recorded
 * subject_type (subject_id comes from the matched route's $subjectParam,
 * "id" by default) but does not combine — the method's wins if set.
 */
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION)]
final class Track
{
    public function __construct(
        public readonly ?string $action = null,
        public readonly ?string $subject = null,
        public readonly string $subjectParam = 'id',
    ) {
    }
}
