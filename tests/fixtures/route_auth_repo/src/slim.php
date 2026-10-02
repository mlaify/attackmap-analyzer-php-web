<?php

use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy;
use Tuupola\Middleware\JwtAuthentication;

$app = AppFactory::create();

$app->post('/orders', function ($request, $response) {
    return $response;
})->add($authMiddleware);

$app->group('/billing', function (RouteCollectorProxy $billing) {
    $billing->post('/invoices', function ($request, $response) {
        return $response;
    });
})->add(new JwtAuthentication(['secret' => getenv('JWT_SECRET')]));

$app->post('/feedback', function ($request, $response) {
    return $response;
})->add(new CorsMiddleware());
