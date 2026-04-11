<?php

session_start();
$hashed = password_hash($password, PASSWORD_DEFAULT);
$isValid = password_verify($password, $hashed);
$jwtSecret = getenv('JWT_SECRET');
$apiKey = $_ENV['API_KEY'];
$serverToken = $_SERVER['ACCESS_TOKEN'];
