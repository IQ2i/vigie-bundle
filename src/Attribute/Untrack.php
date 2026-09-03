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
 * Marks a controller class or action as never recorded, excluding it from a
 * scope otherwise activated by a #[Track] on the class or by
 * http.recorded_paths — an attribute on a method takes precedence over one
 * on its class.
 *
 *     #[Vigie\Untrack]
 *     class AdminController
 *     {
 *         #[Vigie\Track] // re-enabled for this one action
 *         public function delete(): Response {}
 *     }
 */
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION)]
final class Untrack
{
}
