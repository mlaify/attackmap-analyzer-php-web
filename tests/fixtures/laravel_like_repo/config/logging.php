<?php

return [
    'default' => env('LOG_CHANNEL', 'stack'),
    'channels' => [
        'single' => [
            'driver' => 'single',
            'path' => '/var/log/laravel.log',
        ],
    ],
];
