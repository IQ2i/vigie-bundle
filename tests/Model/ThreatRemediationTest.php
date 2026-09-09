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

use IQ2i\VigieBundle\Model\ThreatRemediation;
use PHPUnit\Framework\TestCase;

final class ThreatRemediationTest extends TestCase
{
    public function testBanOutranksCaptchaWhichOutranksThrottleWhichOutranksAnUnknownType(): void
    {
        self::assertGreaterThan(ThreatRemediation::priorityOf('captcha'), ThreatRemediation::priorityOf('ban'));
        self::assertGreaterThan(ThreatRemediation::priorityOf('throttle'), ThreatRemediation::priorityOf('captcha'));
        self::assertGreaterThan(ThreatRemediation::priorityOf('mfa'), ThreatRemediation::priorityOf('throttle'));
    }

    public function testComparisonIsCaseInsensitiveAndTrimmed(): void
    {
        self::assertSame(ThreatRemediation::priorityOf('ban'), ThreatRemediation::priorityOf(' BAN '));
    }
}
