# LazorKit Laravel

A Laravel package for Solana passkey authentication using [LazorKit SDK](https://lazorkit.com). Enable passwordless, biometric authentication (FaceID, TouchID, Windows Hello) for your Laravel applications with Solana smart wallets.

**Author:** [Robert Schmidt](https://robertschmidt.dev)

## Features

- **Passkey Authentication** - WebAuthn-based authentication via biometrics
- **Solana Smart Wallets** - Each passkey creates a Solana smart wallet (PDA)
- **Transaction Signing** - Sign Solana transactions with biometric verification
- **Gasless Transactions** - Optional paymaster integration for sponsored gas fees
- **Wallet Management** - Balance checking, receive addresses, QR codes, transfers
- **Laravel Integration** - Session-based auth, Eloquent models, publishable assets
- **Account Linking** - Link passkeys to existing wallet accounts and vice versa
- **PDA Derivation** - Deterministic smart wallet address derivation (no on-chain calls needed)
- **Linked Account Queries** - Query balance/QR for linked passkey wallets

## Requirements

- PHP 8.2+
- Laravel 11+
- MySQL 8+ or compatible database

## Installation

### Via Composer (Packagist)

```bash
composer require robert-schmidt/laravel-lazorkit
```

### Via Git Submodule

```bash
git submodule add https://github.com/robert-schmidt/laravel-lazorkit.git packages/lazorkit-laravel
```

Then add to your `composer.json`:

```json
{
    "repositories": [
        {
            "type": "path",
            "url": "./packages/lazorkit-laravel"
        }
    ],
    "require": {
        "robert-schmidt/laravel-lazorkit": "@dev"
    }
}
```

Run `composer update`.

## Setup

### 1. Publish Assets

```bash
php artisan vendor:publish --tag=lazorkit-config
php artisan vendor:publish --tag=lazorkit-migrations
php artisan vendor:publish --tag=lazorkit-assets
```

### 2. Run Migrations

```bash
php artisan migrate
```

### 3. Configure Environment

Add to your `.env` file:

```env
# Enable LazorKit
LAZORKIT_ENABLED=true

# Solana Network (devnet, testnet, or mainnet-beta)
LAZORKIT_NETWORK=devnet

# LazorKit Portal URL (for WebAuthn ceremonies)
LAZORKIT_PORTAL_URL=https://portal.lazor.sh

# Paymaster for gasless transactions (optional)
LAZORKIT_PAYMASTER_URL=https://kora.devnet.lazorkit.com
LAZORKIT_USE_PAYMASTER=true

# Session lifetime in seconds (default: 24 hours)
LAZORKIT_SESSION_LIFETIME=86400
```

### 4. Add Trait to Your Wallet User Model

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Lazorkit\Laravel\Traits\HasPasskeyWallet;

class WalletUser extends Model
{
    use HasPasskeyWallet;

    protected $primaryKey = 'wallet_address';
    protected $keyType = 'string';
    public $incrementing = false;

    // ...
}
```

### 5. Import JavaScript Module

The JavaScript module is published to `resources/js/vendor/lazorkit/lazorkit-wallet.js`.

Import it in your application:

```javascript
// ES Module import
import lazorkitWalletManager from './vendor/lazorkit/lazorkit-wallet.js';

// Or make globally available
window.lazorkitWalletManager = lazorkitWalletManager;
```

## Usage

### JavaScript API

```javascript
// Initialize (fetches config from backend automatically)
await lazorkitWalletManager.initialize();

// Connect with passkey (opens portal popup for WebAuthn)
const result = await lazorkitWalletManager.connect();
// Returns: { success: true, walletAddress: '...', authMethod: 'passkey' }

// Check connection status
lazorkitWalletManager.isConnected(); // true/false
lazorkitWalletManager.getWalletAddress(); // '...' or null

// Sign and send transaction
const txResult = await lazorkitWalletManager.signAndSendTransaction({
    instructions: [
        { to: 'recipientAddress', amount_lamports: 1000000 }
    ],
    metadata: { message: 'Payment for services' }
});
// Returns: { success: true, signature: '...', gasless: true }

// Get wallet balance
const balance = await lazorkitWalletManager.getBalance();
// Returns: { lamports: 1000000000, sol: 1.0, formatted: '1.0000 SOL' }

// Send SOL to another wallet
const result = await lazorkitWalletManager.sendTransfer('recipientAddress', 0.5);
// Returns: { success: true, signature: '...', gasless: true }

// Get receive address
const address = lazorkitWalletManager.getReceiveAddress();

// Get QR code for receiving funds
const qrCodeUrl = await lazorkitWalletManager.getReceiveQRCode(200);

// Copy address to clipboard
await lazorkitWalletManager.copyAddress();

// Disconnect
await lazorkitWalletManager.disconnect();
```

### Backend Integration

Check if a user is authenticated with passkey:

```php
// In a controller
$walletAddress = session('wallet_address');
$authMethod = session('auth_method');

if ($walletAddress && $authMethod === 'passkey') {
    // User is authenticated via passkey
}
```

Get the credential for a wallet:

```php
use Lazorkit\Laravel\Services\LazorkitService;

$service = app(LazorkitService::class);
$credential = $service->getCredentialBySmartWallet($walletAddress);
```

## API Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `/api/lazorkit/config` | GET | Get portal configuration |
| `/api/lazorkit/auth/connect` | POST | Authenticate via passkey |
| `/api/lazorkit/auth/disconnect` | POST | Clear session |
| `/api/lazorkit/auth/status` | GET | Check auth status |
| `/api/lazorkit/transaction/prepare` | POST | Prepare transaction for signing |
| `/api/lazorkit/transaction/submit` | POST | Submit signed transaction |
| `/api/lazorkit/wallet/balance` | GET | Get wallet balance (supports `?address=` for linked accounts) |
| `/api/lazorkit/wallet/qr` | GET | Get QR code for wallet address (supports `?address=` for linked accounts) |
| `/api/lazorkit/wallet/info` | GET | Get wallet info with balance |
| `/api/lazorkit/wallet/derive` | POST | Derive smart wallet PDA from credential (no on-chain call) |
| `/api/lazorkit/wallet/lookup` | POST | Look up smart wallet on-chain |
| `/api/lazorkit/wallet/create` | POST | Create smart wallet on-chain via paymaster |

### Linked Account Support

The `/wallet/balance` and `/wallet/qr` endpoints support an optional `address` query parameter to query linked accounts. This enables users who are logged in with a direct wallet to check the balance of their linked passkey wallet:

```
GET /api/lazorkit/wallet/balance?address=LinkedPasskeyWalletAddress
```

Security: The endpoint verifies the requested address is either the session wallet or a linked account before returning data.

## Events

The package dispatches the following Laravel events:

- `Lazorkit\Laravel\Events\PasskeyWalletCreated` - When a new passkey credential is created
- `Lazorkit\Laravel\Events\PasskeyAuthenticated` - When a user authenticates with passkey
- `Lazorkit\Laravel\Events\PasskeyTransactionSigned` - When a transaction is signed

```php
// In EventServiceProvider
protected $listen = [
    \Lazorkit\Laravel\Events\PasskeyAuthenticated::class => [
        \App\Listeners\LogPasskeyLogin::class,
    ],
];
```

## Configuration Options

Full list of configuration options in `config/lazorkit.php`:

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `enabled` | `LAZORKIT_ENABLED` | `false` | Enable/disable the package |
| `network` | `LAZORKIT_NETWORK` | `devnet` | Solana network |
| `portal_url` | `LAZORKIT_PORTAL_URL` | `https://portal.lazor.sh` | LazorKit portal URL |
| `paymaster_url` | `LAZORKIT_PAYMASTER_URL` | `https://kora.devnet.lazorkit.com` | Paymaster URL |
| `use_paymaster` | `LAZORKIT_USE_PAYMASTER` | `true` | Enable gasless transactions |
| `rpc_url` | `LAZORKIT_RPC_URL` | `null` | Custom RPC URL (uses public endpoints if null) |
| `session_lifetime` | `LAZORKIT_SESSION_LIFETIME` | `86400` | Session duration in seconds |
| `allowed_origins` | - | `['https://portal.lazor.sh']` | Allowed origins for postMessage |
| `rate_limits.auth` | `LAZORKIT_RATE_LIMIT_AUTH` | `10` | Auth requests per minute |
| `rate_limits.transaction` | `LAZORKIT_RATE_LIMIT_TRANSACTION` | `5` | Transaction requests per minute |

## Security

- **CSRF Protection** - All POST endpoints use Laravel CSRF tokens
- **Origin Verification** - postMessage communication validates against whitelist
- **Replay Protection** - WebAuthn counter verification prevents replay attacks
- **Rate Limiting** - Configurable rate limits on auth and transaction endpoints
- **Session Security** - Server-side sessions with httpOnly cookies

## How It Works

### Authentication Flow

```
User clicks "Connect with Passkey"
    ↓
Opens popup → portal.lazor.sh/connect
    ↓
WebAuthn ceremony (FaceID/TouchID/Windows Hello)
    ↓
Portal creates/retrieves credential
    ↓
Portal posts message with: credentialId, smartWalletAddress, publicKey
    ↓
JS sends to /api/lazorkit/auth/connect
    ↓
Backend validates, stores credential, creates session
    ↓
User authenticated with smart wallet address
```

### Transaction Flow

```
User initiates transaction
    ↓
Backend prepares transaction (/api/lazorkit/transaction/prepare)
    ↓
Opens popup → portal.lazor.sh/sign
    ↓
User approves with passkey (biometric)
    ↓
Portal signs with secp256r1, returns serialized tx
    ↓
JS sends to /api/lazorkit/transaction/submit
    ↓
Backend submits via paymaster (gasless) or direct to Solana
    ↓
Transaction confirmed
```

## Database Schema

### passkey_credentials

| Column | Type | Description |
|--------|------|-------------|
| `id` | ULID | Primary key |
| `credential_id` | string | WebAuthn credential ID (unique) |
| `public_key` | text | P-256 public key |
| `smart_wallet_address` | string | Solana PDA address (unique) |
| `counter` | integer | Replay protection counter |
| `device_info` | text | Device/browser info (nullable) |
| `last_used_at` | timestamp | Last authentication time |

## Troubleshooting

### Popup Blocked

Users need to allow popups for your domain. The package will throw an error if the popup is blocked.

### WebAuthn Not Supported

Check browser support with:

```javascript
if (lazorkitWalletManager.isAvailable()) {
    // WebAuthn is supported
}
```

### Session Expired

Sessions expire based on `LAZORKIT_SESSION_LIFETIME`. Users will need to re-authenticate.

## Important Notes

- **Pre-Audit Status**: LazorKit is currently pre-audit. This package is intended for development, testing, and beta environments. Use in production at your own discretion.
- **Smart Wallet Architecture**: Passkeys use secp256r1 (P-256) curve, not Ed25519. LazorKit creates smart wallets (PDAs) that verify passkey signatures on-chain.
- **Portal Dependency**: Authentication relies on `portal.lazor.sh` availability.

## Contributing

Contributions are welcome! Please submit pull requests to the [GitHub repository](https://github.com/robert-schmidt/laravel-lazorkit).

## License

MIT License - see [LICENSE](LICENSE) file.

## Credits

- [LazorKit](https://lazorkit.com) - Passkey infrastructure for Solana
- [Robert Schmidt](https://robertschmidt.dev) - Package author
