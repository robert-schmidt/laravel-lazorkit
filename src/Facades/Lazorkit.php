<?php

namespace Lazorkit\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use Lazorkit\Laravel\Services\LazorkitService;

/**
 * @method static bool isEnabled()
 * @method static array validatePortalResponse(array $data)
 * @method static \Lazorkit\Laravel\Models\PasskeyCredential createOrUpdateCredential(array $validatedData, ?string $userAgent = null)
 * @method static bool verifyCredential(string $credentialId, int $counter)
 * @method static \Lazorkit\Laravel\Models\PasskeyCredential|null getCredentialBySmartWallet(string $smartWalletAddress)
 * @method static array getPortalConfig()
 *
 * @see \Lazorkit\Laravel\Services\LazorkitService
 */
class Lazorkit extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return LazorkitService::class;
    }
}
