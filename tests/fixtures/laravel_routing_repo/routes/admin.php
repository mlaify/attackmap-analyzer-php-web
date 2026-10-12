<?php

use App\Http\Controllers\AuditController;
use Illuminate\Support\Facades\Route;

Route::get('audit', [AuditController::class, 'index']);
