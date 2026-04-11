<?php

$ch = curl_init("https://api.example.com/v1/ping");
$json = file_get_contents("https://payments.example.com/check");
$client->request('POST', 'https://hooks.example.com/notify', ['json' => ['ok' => true]]);
