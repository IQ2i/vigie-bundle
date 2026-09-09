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

namespace IQ2i\VigieBundle\Tests\Functional;

use IQ2i\VigieBundle\Tests\TestApplication\Kernel;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

abstract class FunctionalTestCase extends WebTestCase
{
    /**
     * @param array<string, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        /** @var string $environment */
        $environment = $options['environment'] ?? 'test';

        // Debug mode is off everywhere except the "profiler" environment, which needs it to register the
        // Vigie panel; otherwise kept off to avoid dumping a config reference file into the source tree.
        return new Kernel($environment, 'profiler' === $environment);
    }
}
