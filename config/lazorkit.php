<?php

return [
    /*
    |--------------------------------------------------------------------------
    | LazorKit Enabled
    |--------------------------------------------------------------------------
    |
    | Enable or disable LazorKit passkey authentication. When disabled,
    | the package routes will not be registered and the feature will
    | not appear in authentication method options.
    |
    */
    'enabled' => env('LAZORKIT_ENABLED', false),

    /*
    |--------------------------------------------------------------------------
    | Portal URL
    |--------------------------------------------------------------------------
    |
    | The LazorKit portal URL for passkey authentication. This is where
    | users are redirected to complete WebAuthn ceremonies (FaceID,
    | TouchID, Windows Hello).
    |
    */
    'portal_url' => env('LAZORKIT_PORTAL_URL', 'https://portal.lazor.sh'),

    /*
    |--------------------------------------------------------------------------
    | Paymaster URL
    |--------------------------------------------------------------------------
    |
    | The LazorKit paymaster URL for gasless transactions. When enabled,
    | transactions will be submitted through the paymaster to sponsor
    | gas fees for users.
    |
    */
    'paymaster_url' => env('LAZORKIT_PAYMASTER_URL', 'https://kora.devnet.lazorkit.com'),

    /*
    |--------------------------------------------------------------------------
    | Solana Network
    |--------------------------------------------------------------------------
    |
    | The Solana network to connect to. Options are 'devnet', 'testnet',
    | or 'mainnet-beta'. This affects RPC URL selection if not explicitly set.
    |
    */
    'network' => env('LAZORKIT_NETWORK', 'devnet'),

    /*
    |--------------------------------------------------------------------------
    | RPC URL
    |--------------------------------------------------------------------------
    |
    | The Solana RPC URL to use for transactions. If null, the package
    | will use public RPC endpoints based on the network setting.
    |
    */
    'rpc_url' => env('LAZORKIT_RPC_URL', null),

    /*
    |--------------------------------------------------------------------------
    | Use Paymaster
    |--------------------------------------------------------------------------
    |
    | Whether to use the paymaster for gasless transactions. When enabled,
    | the paymaster will sponsor transaction fees. If the paymaster is
    | unavailable, it will fall back to direct submission.
    |
    */
    'use_paymaster' => env('LAZORKIT_USE_PAYMASTER', true),

    /*
    |--------------------------------------------------------------------------
    | Allowed Origins
    |--------------------------------------------------------------------------
    |
    | Origins allowed for postMessage communication from the LazorKit
    | portal. Add additional origins if using a custom portal deployment.
    |
    */
    'allowed_origins' => [
        'https://portal.lazor.sh',
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Lifetime
    |--------------------------------------------------------------------------
    |
    | How long a passkey session remains valid in seconds. After this
    | time, users will need to re-authenticate with their passkey.
    |
    */
    'session_lifetime' => env('LAZORKIT_SESSION_LIFETIME', 86400), // 24 hours

    /*
    |--------------------------------------------------------------------------
    | Credential Lifetime
    |--------------------------------------------------------------------------
    |
    | How long a stored credential remains valid without use in seconds.
    | Credentials not used within this period may be considered stale.
    |
    */
    'credential_lifetime' => env('LAZORKIT_CREDENTIAL_LIFETIME', 2592000), // 30 days

    /*
    |--------------------------------------------------------------------------
    | Rate Limits
    |--------------------------------------------------------------------------
    |
    | Rate limiting configuration for authentication and transaction
    | endpoints to prevent abuse and brute force attacks.
    |
    */
    'rate_limits' => [
        'auth' => env('LAZORKIT_RATE_LIMIT_AUTH', 10), // per minute
        'transaction' => env('LAZORKIT_RATE_LIMIT_TRANSACTION', 5), // per minute
    ],

    /*
    |--------------------------------------------------------------------------
    | Wallet User Model
    |--------------------------------------------------------------------------
    |
    | The fully qualified class name of the model used for wallet users.
    | This model should use the HasPasskeyWallet trait to enable
    | passkey credential relationships.
    |
    */
    'wallet_user_model' => env('LAZORKIT_WALLET_USER_MODEL', \App\Models\WalletUser::class),

    /*
    |--------------------------------------------------------------------------
    | Route Prefix
    |--------------------------------------------------------------------------
    |
    | The prefix for all LazorKit API routes. You can customize this
    | to fit your application's routing structure.
    |
    */
    'route_prefix' => env('LAZORKIT_ROUTE_PREFIX', 'api/lazorkit'),

    /*
    |--------------------------------------------------------------------------
    | Route Middleware
    |--------------------------------------------------------------------------
    |
    | Middleware to apply to all LazorKit routes. The 'web' middleware
    | is required for session handling and CSRF protection.
    |
    */
    'route_middleware' => ['web'],
];
