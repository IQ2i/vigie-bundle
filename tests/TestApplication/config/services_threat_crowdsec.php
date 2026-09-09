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

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set('app.mock_response', MockResponse::class)
        ->args(['{"new":[{"id":1,"type":"ban","scope":"Ip","value":"1.2.3.4","duration":"4h"}],"deleted":[]}'])
        ->public();

    $container->services()
        ->set('app.mock_http_client', MockHttpClient::class)
        ->args([[service('app.mock_response')]])
        ->public();
};
