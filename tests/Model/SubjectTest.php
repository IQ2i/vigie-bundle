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

namespace IQ2i\VigieBundle\Tests\Model;

use IQ2i\VigieBundle\Model\Subject;
use PHPUnit\Framework\TestCase;

final class SubjectTest extends TestCase
{
    public function testIdIsCastToString(): void
    {
        $subject = new Subject('user', 42);

        self::assertSame('user', $subject->type);
        self::assertSame('42', $subject->id);
    }

    public function testStringIdIsKeptAsIs(): void
    {
        $subject = new Subject('order', 'ord_abc123');

        self::assertSame('ord_abc123', $subject->id);
    }
}
