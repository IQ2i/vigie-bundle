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

namespace IQ2i\VigieBundle\Command;

use Symfony\Component\Console\Input\InputInterface;

/**
 * Shared option parsing for the `vigie:*` commands: an out-of-range `--limit`
 * must fail cleanly (`Command::INVALID` and a message), never surface as a
 * raw PHP warning or a silently-clamped-to-zero cast.
 *
 * @internal
 */
final class InputParser
{
    /**
     * @throws \InvalidArgumentException when the option is set but not an integer in range
     */
    public static function int(InputInterface $input, string $option, int $min, ?int $max = null): ?int
    {
        $value = $input->getOption($option);

        if (null === $value) {
            return null;
        }

        if (!\is_string($value) && !\is_int($value)) {
            throw new \InvalidArgumentException(\sprintf('Option "--%s" must be an integer.', $option));
        }

        $range = null !== $max ? ['min_range' => $min, 'max_range' => $max] : ['min_range' => $min];
        $result = filter_var($value, \FILTER_VALIDATE_INT, ['options' => $range]);

        if (false === $result) {
            throw new \InvalidArgumentException(null !== $max ? \sprintf('Option "--%s" must be an integer between %d and %d, got "%s".', $option, $min, $max, (string) $value) : \sprintf('Option "--%s" must be an integer of at least %d, got "%s".', $option, $min, (string) $value));
        }

        return $result;
    }
}
