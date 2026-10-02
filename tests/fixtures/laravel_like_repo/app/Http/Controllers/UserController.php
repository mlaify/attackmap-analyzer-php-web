<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserController
{
    public function show(Request $request, $cache, $config, $session)
    {
        // Request / cache / config / session getters are not routes.
        $id = $request->get('id');
        $user = $cache->get('user:' . $id);
        $ttl = $config->get('/cache/ttl');
        $flash = $session->get('flash');

        // Non-secret connection settings.
        $host = getenv('DB_HOST');
        $base = getenv('API_URL');
        // Secret-shaped names.
        $password = getenv('DB_PASSWORD');
        $key = $_ENV['API_KEY'];

        // A variable named like a JWT and an unrelated auth() method.
        $jwtSecretRotationDays = 30;
        $this->auth($user);

        return compact('id', 'user', 'ttl', 'flash', 'host', 'base', 'password', 'key');
    }

    private function auth($user): bool
    {
        return $user !== null;
    }
}
