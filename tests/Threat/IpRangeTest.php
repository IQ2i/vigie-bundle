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

namespace IQ2i\VigieBundle\Tests\Threat;

use IQ2i\VigieBundle\Threat\IpRange;
use PHPUnit\Framework\TestCase;

final class IpRangeTest extends TestCase
{
    public function testPackingAnInvalidAddressReturnsNull(): void
    {
        self::assertNull(IpRange::pack('not-an-ip'));
        self::assertNull(IpRange::pack('999.999.999.999'));
        self::assertNull(IpRange::pack(''));
    }

    public function testAnIpv4AndTheEquivalentIpv4MappedIpv6AddressPackToTheSameBytes(): void
    {
        self::assertSame(IpRange::pack('1.2.3.4'), IpRange::pack('::ffff:1.2.3.4'));
    }

    public function testParsingABareIpReturnsADegenerateRange(): void
    {
        $range = IpRange::parse('1.2.3.4');

        self::assertNotNull($range);
        self::assertSame($range[0], $range[1]);
        self::assertSame(IpRange::pack('1.2.3.4'), $range[0]);
    }

    public function testParsingAnIpv4Cidr(): void
    {
        $range = IpRange::parse('1.2.3.0/24');

        self::assertNotNull($range);
        self::assertSame(IpRange::pack('1.2.3.0'), $range[0]);
        self::assertSame(IpRange::pack('1.2.3.255'), $range[1]);
    }

    public function testAnAddressInsideAParsedIpv4CidrFallsBetweenItsBounds(): void
    {
        $range = IpRange::parse('1.2.3.0/24');
        $inside = IpRange::pack('1.2.3.42');

        self::assertNotNull($range);
        self::assertNotNull($inside);
        self::assertTrue(strcmp($range[0], $inside) <= 0);
        self::assertTrue(strcmp($inside, $range[1]) <= 0);
    }

    public function testAnAddressOutsideAParsedIpv4CidrFallsOutsideItsBounds(): void
    {
        $range = IpRange::parse('1.2.3.0/24');
        $outside = IpRange::pack('1.2.4.1');

        self::assertNotNull($range);
        self::assertNotNull($outside);
        self::assertTrue(strcmp($outside, $range[1]) > 0);
    }

    public function testParsingASlash32IsADegenerateRange(): void
    {
        $range = IpRange::parse('1.2.3.4/32');

        self::assertNotNull($range);
        self::assertSame($range[0], $range[1]);
        self::assertSame(IpRange::pack('1.2.3.4'), $range[0]);
    }

    public function testParsingASlashZeroCoversTheWholeIpv4Space(): void
    {
        $range = IpRange::parse('0.0.0.0/0');

        self::assertNotNull($range);
        self::assertSame(IpRange::pack('0.0.0.0'), $range[0]);
        self::assertSame(IpRange::pack('255.255.255.255'), $range[1]);
    }

    public function testParsingAnIpv6Cidr(): void
    {
        $range = IpRange::parse('2001:db8::/32');

        self::assertNotNull($range);
        self::assertSame(IpRange::pack('2001:db8::'), $range[0]);
        self::assertSame(IpRange::pack('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'), $range[1]);
    }

    public function testParsingAnIpv4MappedIpv6CidrCountsItsPrefixOver128Bits(): void
    {
        $range = IpRange::parse('::ffff:1.2.3.0/120');

        self::assertNotNull($range);
        self::assertSame(IpRange::pack('1.2.3.0'), $range[0]);
        self::assertSame(IpRange::pack('1.2.3.255'), $range[1]);
    }

    public function testParsingAnInvalidPrefixReturnsNull(): void
    {
        self::assertNull(IpRange::parse('1.2.3.0/33'));
        self::assertNull(IpRange::parse('1.2.3.0/-1'));
        self::assertNull(IpRange::parse('1.2.3.0/abc'));
    }

    public function testParsingAnInvalidAddressReturnsNull(): void
    {
        self::assertNull(IpRange::parse('not-an-ip/24'));
        self::assertNull(IpRange::parse('not-an-ip'));
    }
}
