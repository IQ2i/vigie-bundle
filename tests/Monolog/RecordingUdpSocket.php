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

namespace IQ2i\VigieBundle\Tests\Monolog;

use Monolog\Handler\SyslogUdp\UdpSocket;

/**
 * Keeps every datagram in memory instead of sending it.
 */
final class RecordingUdpSocket extends UdpSocket
{
    /**
     * @var list<string>
     */
    public array $sent = [];

    protected function send(string $chunk): void
    {
        $this->sent[] = $chunk;
    }
}
