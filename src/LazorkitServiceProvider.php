<?php

namespace Lazorkit\Laravel;

use Illuminate\Support\ServiceProvider;
use Lazorkit\Laravel\Services\LazorkitService;
use Lazorkit\Laravel\Services\LazorkitWalletService;
use Lazorkit\Laravel\Services\PaymasterService;

class LazorkitServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/lazorkit.php',
            'lazorkit'
        );

        // Register LazorkitService as singleton
        $this->app->singleton(LazorkitService::class, function ($app) {
            return new LazorkitService(config('lazorkit'));
        });

        // Register PaymasterService as singleton
        $this->app->singleton(PaymasterService::class, function ($app) {
            return new PaymasterService();
        });

        // Register LazorkitWalletService as singleton
        $this->app->singleton(LazorkitWalletService::class, function ($app) {
            return new LazorkitWalletService(
                $app->make(LazorkitService::class),
                $app->make(PaymasterService::class)
            );
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Publish configuration
        $this->publishes([
            __DIR__ . '/../config/lazorkit.php' => config_path('lazorkit.php'),
        ], 'lazorkit-config');

        // Publish migrations
        $this->publishes([
            __DIR__ . '/../database/migrations/' => database_path('migrations'),
        ], 'lazorkit-migrations');

        // Publish JavaScript assets
        $this->publishes([
            __DIR__ . '/../resources/js/' => resource_path('js/vendor/lazorkit'),
        ], 'lazorkit-assets');

        // Load routes if package is enabled
        if (config('lazorkit.enabled', false)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/api.php');
        }

        // Load migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }
}
