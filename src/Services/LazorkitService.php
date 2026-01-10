<?php

namespace Lazorkit\Laravel\Services;

use Lazorkit\Laravel\Models\PasskeyCredential;
use Lazorkit\Laravel\Events\PasskeyAuthenticated;
use Lazorkit\Laravel\Events\PasskeyWalletCreated;
use Lazorkit\Laravel\Exceptions\PasskeyValidationException;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class LazorkitService
{
    private array $config;
    private string $portalUrl;
    private string $paymasterUrl;
    private ?string $rpcUrl;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->portalUrl = $config['portal_url'] ?? 'https://portal.lazor.sh';
        $this->paymasterUrl = $config['paymaster_url'] ?? 'https://kora.devnet.lazorkit.com';
        $this->rpcUrl = $config['rpc_url'] ?? null;
    }

    /**
     * Check if LazorKit is enabled.
     */
    public function isEnabled(): bool
    {
        return (bool) ($this->config['enabled'] ?? false);
    }

    /**
     * Validate response data from LazorKit portal.
     *
     * @throws PasskeyValidationException
     */
    public function validatePortalResponse(array $data): array
    {
        // Required fields from portal
        $required = ['credentialId', 'smartWalletAddress', 'publicKey'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new PasskeyValidationException("Missing required field: {$field}");
            }
        }

        // Validate Solana address format (base58, 32-44 chars)
        if (!preg_match('/^[1-9A-HJ-NP-Za-km-z]{32,44}$/', $data['smartWalletAddress'])) {
            throw new PasskeyValidationException('Invalid smart wallet address format');
        }

        // Validate credential ID (base64url format)
        if (!preg_match('/^[A-Za-z0-9_-]+$/', $data['credentialId'])) {
            throw new PasskeyValidationException('Invalid credential ID format');
        }

        // Validate public key is present and reasonably formatted
        if (strlen($data['publicKey']) < 40) {
            throw new PasskeyValidationException('Invalid public key format');
        }

        // Validate counter if present
        if (isset($data['counter']) && (!is_numeric($data['counter']) || $data['counter'] < 0)) {
            throw new PasskeyValidationException('Invalid counter value');
        }

        return $data;
    }

    /**
     * Create or update a passkey credential.
     */
    public function createOrUpdateCredential(array $validatedData, ?string $userAgent = null): PasskeyCredential
    {
        $credential = PasskeyCredential::updateOrCreate(
            ['credential_id' => $validatedData['credentialId']],
            [
                'public_key' => $validatedData['publicKey'],
                'smart_wallet_address' => $validatedData['smartWalletAddress'],
                'user_agent' => $userAgent ? substr($userAgent, 0, 500) : null,
                'counter' => $validatedData['counter'] ?? 0,
                'last_used_at' => now(),
            ]
        );

        // Fire appropriate event
        if ($credential->wasRecentlyCreated) {
            event(new PasskeyWalletCreated($credential));
            Log::info('New passkey credential created', [
                'smart_wallet' => $credential->smart_wallet_address,
            ]);
        } else {
            event(new PasskeyAuthenticated($credential));
            Log::info('Passkey authentication successful', [
                'smart_wallet' => $credential->smart_wallet_address,
            ]);
        }

        return $credential;
    }

    /**
     * Verify a credential and its counter for replay protection.
     */
    public function verifyCredential(string $credentialId, int $counter): bool
    {
        $credential = PasskeyCredential::where('credential_id', $credentialId)->first();

        if (!$credential) {
            Log::warning('Passkey credential not found', [
                'credential_id' => substr($credentialId, 0, 20) . '...',
            ]);
            return false;
        }

        // Verify counter is greater than stored (replay protection)
        if ($counter <= $credential->counter) {
            Log::warning('Passkey replay attack detected', [
                'credential_id' => substr($credentialId, 0, 20) . '...',
                'stored_counter' => $credential->counter,
                'received_counter' => $counter,
            ]);
            return false;
        }

        // Update counter and last used timestamp
        $credential->update([
            'counter' => $counter,
            'last_used_at' => now(),
        ]);

        return true;
    }

    /**
     * Get credential by smart wallet address.
     */
    public function getCredentialBySmartWallet(string $smartWalletAddress): ?PasskeyCredential
    {
        return PasskeyCredential::where('smart_wallet_address', $smartWalletAddress)->first();
    }

    /**
     * Get credential by credential ID.
     */
    public function getCredentialById(string $credentialId): ?PasskeyCredential
    {
        return PasskeyCredential::where('credential_id', $credentialId)->first();
    }

    /**
     * Get the portal configuration for the frontend.
     */
    public function getPortalConfig(): array
    {
        return [
            'portalUrl' => $this->portalUrl,
            'paymasterUrl' => $this->paymasterUrl,
            'rpcUrl' => $this->rpcUrl,
            'enabled' => $this->isEnabled(),
            'allowedOrigins' => $this->config['allowed_origins'] ?? ['https://portal.lazor.sh'],
        ];
    }

    /**
     * Get the portal URL.
     */
    public function getPortalUrl(): string
    {
        return $this->portalUrl;
    }

    /**
     * Get the paymaster URL.
     */
    public function getPaymasterUrl(): string
    {
        return $this->paymasterUrl;
    }

    /**
     * Get the RPC URL.
     */
    public function getRpcUrl(): ?string
    {
        return $this->rpcUrl;
    }

    /**
     * Clean up expired/stale credentials.
     */
    public function cleanupStaleCredentials(): int
    {
        $lifetime = $this->config['credential_lifetime'] ?? (30 * 86400);
        $cutoff = now()->subSeconds($lifetime);

        $count = PasskeyCredential::where('last_used_at', '<', $cutoff)
            ->orWhereNull('last_used_at')
            ->where('created_at', '<', $cutoff)
            ->delete();

        if ($count > 0) {
            Log::info('Cleaned up stale passkey credentials', ['count' => $count]);
        }

        return $count;
    }
}
