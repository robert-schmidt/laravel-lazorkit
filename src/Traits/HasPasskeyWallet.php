<?php

namespace Lazorkit\Laravel\Traits;

use Lazorkit\Laravel\Models\PasskeyCredential;
use Illuminate\Database\Eloquent\Relations\HasMany;

trait HasPasskeyWallet
{
    /**
     * Get the passkey credentials for this wallet user.
     */
    public function passkeyCredentials(): HasMany
    {
        return $this->hasMany(PasskeyCredential::class, 'smart_wallet_address', 'wallet_address');
    }

    /**
     * Check if this user authenticated via passkey.
     */
    public function isPasskeyUser(): bool
    {
        return $this->auth_method === 'passkey' || $this->passkeyCredentials()->exists();
    }

    /**
     * Get the primary (most recently used) passkey credential.
     */
    public function primaryPasskeyCredential(): ?PasskeyCredential
    {
        return $this->passkeyCredentials()
            ->orderBy('last_used_at', 'desc')
            ->first();
    }

    /**
     * Get all active passkey credentials (used within last 30 days).
     */
    public function activePasskeyCredentials()
    {
        return $this->passkeyCredentials()->active();
    }

    /**
     * Check if user has any valid passkey credentials.
     */
    public function hasValidPasskey(): bool
    {
        return $this->passkeyCredentials()
            ->get()
            ->contains(fn ($credential) => $credential->isValid());
    }

    /**
     * Get the smart wallet address from the most recent passkey.
     */
    public function getSmartWalletAddress(): ?string
    {
        $credential = $this->primaryPasskeyCredential();
        return $credential?->smart_wallet_address;
    }

    /**
     * Revoke all passkey credentials for this user.
     */
    public function revokeAllPasskeys(): int
    {
        return $this->passkeyCredentials()->delete();
    }

    /**
     * Revoke a specific passkey credential.
     */
    public function revokePasskey(string $credentialId): bool
    {
        return $this->passkeyCredentials()
            ->where('credential_id', $credentialId)
            ->delete() > 0;
    }
}
