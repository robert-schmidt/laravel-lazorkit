<?php

namespace Lazorkit\Laravel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PasskeyCredential extends Model
{
    use HasUlids;

    /**
     * The table associated with the model.
     */
    protected $table = 'passkey_credentials';

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'credential_id',
        'public_key',
        'smart_wallet_address',
        'user_agent',
        'counter',
        'wallet_address',
        'last_used_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'counter' => 'integer',
        'last_used_at' => 'datetime',
    ];

    /**
     * The attributes that should be hidden for serialization.
     */
    protected $hidden = [
        'public_key', // Don't expose in API responses
    ];

    /**
     * Get the WalletUser associated with this credential.
     */
    public function walletUser(): BelongsTo
    {
        $walletUserClass = config('lazorkit.wallet_user_model', \App\Models\WalletUser::class);
        return $this->belongsTo($walletUserClass, 'smart_wallet_address', 'wallet_address');
    }

    /**
     * Scope for active credentials (used within last 30 days).
     */
    public function scopeActive($query)
    {
        return $query->where('last_used_at', '>=', now()->subDays(30));
    }

    /**
     * Scope for credentials belonging to a specific smart wallet.
     */
    public function scopeForSmartWallet($query, string $smartWalletAddress)
    {
        return $query->where('smart_wallet_address', $smartWalletAddress);
    }

    /**
     * Check if credential is still valid based on configured lifetime.
     */
    public function isValid(): bool
    {
        // Credential is valid if used within the configured lifetime
        $lifetime = config('lazorkit.credential_lifetime', 86400 * 30); // 30 days default

        if (!$this->last_used_at) {
            return true; // New credential
        }

        return $this->last_used_at->addSeconds($lifetime)->isFuture();
    }

    /**
     * Check if this credential was recently created.
     */
    public function isNew(): bool
    {
        return $this->created_at->diffInMinutes(now()) < 5;
    }

    /**
     * Update the last used timestamp.
     */
    public function touch(): bool
    {
        $this->last_used_at = now();
        return $this->save();
    }

    /**
     * Increment the counter for replay protection.
     */
    public function incrementCounter(int $newCounter): bool
    {
        if ($newCounter <= $this->counter) {
            return false; // Replay attack detected
        }

        $this->counter = $newCounter;
        $this->last_used_at = now();
        return $this->save();
    }
}
