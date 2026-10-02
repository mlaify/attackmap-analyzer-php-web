<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy;

$api = AppFactory::create();

$api->get('/status', function ($request, $response) {
    return $response;
});

$api->group('/v1', function (RouteCollectorProxy $v1) {
    $v1->post('/tokens', function ($request, $response) {
        $claims = JWT::decode($request->getHeaderLine('Authorization'), new Key(getenv('JWT_SECRET'), 'HS256'));
        return $response;
    });
});

$api->run();
