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

namespace IQ2i\VigieBundle\Monolog;

use Monolog\Formatter\FormatterInterface;
use Monolog\Handler\HandlerInterface;
use Monolog\Handler\NullHandler;
use Monolog\Handler\SyslogHandler;
use Monolog\Handler\SyslogUdpHandler;

/**
 * Builds the handler behind iq2i_vigie.output.syslog. Every argument may come from an env placeholder, so it
 * is only read when the service is first needed, never at container compile time.
 *
 * @internal
 */
final class SyslogHandlerFactory
{
    public static function create(
        bool|string $enabled,
        ?string $host,
        int|string $port,
        string $facility,
        string $ident,
        int|string $maxLength,
        FormatterInterface $formatter,
    ): HandlerInterface {
        // Checked before anything is instantiated: SyslogUdpHandler throws at construction without ext-sockets.
        if (!filter_var($enabled, \FILTER_VALIDATE_BOOL)) {
            return new NullHandler();
        }

        if ((int) $port < 1 || (int) $maxLength < 1) {
            throw new \InvalidArgumentException(\sprintf('iq2i_vigie.output.syslog: port and max_length must be positive, got port "%s" and max_length "%s".', $port, $maxLength));
        }

        $handler = null === $host || '' === $host
            ? new SyslogHandler($ident, $facility)
            : new SyslogUdpHandler($host, (int) $port, $facility, ident: $ident, maxLength: (int) $maxLength);

        return $handler->setFormatter($formatter);
    }
}
