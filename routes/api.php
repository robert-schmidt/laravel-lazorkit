<?php

use Illuminate\Support\Facades\Route;
use Lazorkit\Laravel\Http\Controllers\LazorkitController;
use Lazorkit\Laravel\Http\Middleware\LazorkitRateLimiter;

/*
|--------------------------------------------------------------------------
| LazorKit API Routes
|--------------------------------------------------------------------------
|
| These routes handle passkey authentication and transaction signing
| for the LazorKit smart wallet integration.
|
*/

$prefix = config('lazorkit.route_prefix', 'api/lazorkit');
$middleware = array_merge(
    config('lazorkit.route_middleware', ['web']),
    [LazorkitRateLimiter::class]
);

Route::prefix($prefix)
    ->middleware($middleware)
    ->group(function () {
        // Configuration endpoint (public)
        Route::get('/config', [LazorkitController::class, 'getConfig'])
            ->name('lazorkit.config');

        // Authentication endpoints
        Route::post('/auth/connect', [LazorkitController::class, 'connect'])
            ->name('lazorkit.auth.connect');

        Route::post('/auth/disconnect', [LazorkitController::class, 'disconnect'])
            ->name('lazorkit.auth.disconnect');

        Route::get('/auth/status', [LazorkitController::class, 'status'])
            ->name('lazorkit.auth.status');

        // Smart wallet derive (compute PDA from credential - no on-chain call)
        Route::post('/wallet/derive', [LazorkitController::class, 'deriveSmartWallet'])
            ->name('lazorkit.wallet.derive');

        // Smart wallet lookup (verify wallet exists on-chain)
        Route::post('/wallet/lookup', [LazorkitController::class, 'lookupSmartWallet'])
            ->name('lazorkit.wallet.lookup');

        // Smart wallet creation (create on-chain via paymaster)
        Route::post('/wallet/create', [LazorkitController::class, 'createSmartWallet'])
            ->name('lazorkit.wallet.create');

        // Transaction endpoints (require authentication)
        Route::post('/transaction/prepare', [LazorkitController::class, 'prepareTransaction'])
            ->name('lazorkit.transaction.prepare');

        Route::post('/transaction/submit', [LazorkitController::class, 'submitTransaction'])
            ->name('lazorkit.transaction.submit');

        Route::get('/transaction/{signature}/status', [LazorkitController::class, 'getTransactionStatus'])
            ->name('lazorkit.transaction.status');

        // Wallet management endpoints
        Route::get('/wallet/balance', [LazorkitController::class, 'getBalance'])
            ->name('lazorkit.wallet.balance');

        Route::get('/wallet/qr', [LazorkitController::class, 'getQRCode'])
            ->name('lazorkit.wallet.qr');

        Route::get('/wallet/info', [LazorkitController::class, 'getWalletInfo'])
            ->name('lazorkit.wallet.info');
    });
