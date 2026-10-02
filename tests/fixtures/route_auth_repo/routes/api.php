<?php

use App\Http\Controllers\ContactController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

// Group guard: every route inside requires a Sanctum token...
Route::middleware(['auth:sanctum', 'throttle:api'])->group(function () {
    Route::post('/posts', [PostController::class, 'store']);
    Route::delete('/posts/{id}', [PostController::class, 'destroy']);
    // ...except this one, which opts out of the group's guard.
    Route::post('/posts/preview', [PostController::class, 'preview'])->withoutMiddleware('auth:sanctum');
});

// Route-local guard.
Route::patch('/settings', 'SettingsController@update')->middleware('auth');

// Controller constructor guard, with an `except` opt-out for `show`.
Route::put('/profile', [ProfileController::class, 'update']);
Route::get('/profile/{id}', [ProfileController::class, 'show']);

// Nothing says either way.
Route::post('/contact', [ContactController::class, 'send']);
