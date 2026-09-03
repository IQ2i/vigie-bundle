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

namespace IQ2i\VigieBundle\Uid;

use Symfony\Component\Uid\Uuid;

/**
 * @internal
 */
final class UidGenerator
{
    private function __construct()
    {
    }

    /**
     * Falls back to random bytes when symfony/uid isn't installed — still
     * unique, just not sortable/timestamped.
     */
    public static function generate(): string
    {
        return class_exists(Uuid::class) ? Uuid::v7()->toRfc4122() : bin2hex(random_bytes(16));
    }
}
