<?php

use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

Route::get('/users/{id}', [UserController::class, 'show'])->middleware('auth:sanctum');
Route::post('/users', [UserController::class, 'store']);
