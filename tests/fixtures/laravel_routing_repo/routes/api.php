<?php

use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\BothController;
use App\Http\Controllers\PhotoController;
use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

// Laravel mounts routes/api.php under /api.
Route::middleware(['auth:sanctum'])->prefix('admin')->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});

Route::match(['get', 'post'], '/both', [BothController::class, 'handle']);

Route::resource('photos', PhotoController::class);
Route::apiResource('posts', PostController::class);
