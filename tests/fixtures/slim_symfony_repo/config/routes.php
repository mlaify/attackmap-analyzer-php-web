<?php

return [
    'routes' => [
        [
            'path' => '/api/ping',
            'middleware' => App\Handler\PingHandler::class,
            'allowed_methods' => ['GET'],
        ],
    ],
];
