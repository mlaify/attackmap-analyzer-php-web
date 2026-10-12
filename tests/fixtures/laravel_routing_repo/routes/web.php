<?php

use App\Http\Controllers\CommentController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\InvoiceController;
use App\Http\Controllers\ReportController;
use App\Http\Controllers\TagController;
use Illuminate\Support\Facades\Route;

// Legacy array group with a nested fluent group inside it.
Route::group(['prefix' => 'dashboard', 'middleware' => ['web', 'auth']], function () {
    Route::get('/', [DashboardController::class, 'index']);
    Route::prefix('reports/')->name('reports.')->group(function () {
        Route::get('{report}', [ReportController::class, 'show']);
        // A brace and a quote in a string don't end the group: "}" ')'
        Route::post('export', [ReportController::class, 'export'])->withoutMiddleware('auth');
    });
});

// Middleware chained before a verb (no group).
Route::middleware('auth')->delete('/account', [DashboardController::class, 'destroy']);
Route::prefix('v1')->get('status', fn () => 'ok');

// Resources with only/except, nested, shallow and the plural form.
Route::resource('invoices', InvoiceController::class)->only(['index', 'show']);
Route::resource('tags', TagController::class, ['except' => ['create', 'edit']]);
Route::resource('photos.comments', CommentController::class)->shallow()->only('index', 'update');
Route::resources([
    'teams' => TeamController::class,
]);

// Controller groups dispatch bare method names.
Route::controller(ReportController::class)->group(function () {
    Route::get('/archive', 'archive');
});

// Route::get('/commented-out', [DashboardController::class, 'old']);
/* Route::post('/also-commented', [DashboardController::class, 'old']); */
$help = <<<TXT
Route::get('/in-heredoc', 'x') ) ( }
TXT;

Route::get('/after-heredoc', [DashboardController::class, 'help']);

require __DIR__.'/auth.php';
