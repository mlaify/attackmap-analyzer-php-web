<?php

use Slim\Factory\AppFactory;

$app = AppFactory::create();
$app->get('/health', function ($request, $response) {
    return $response;
});

Route::post('/login', [AuthController::class, 'login']);
