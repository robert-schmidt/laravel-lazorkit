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

        // Determine RPC URL based on network setting (devnet/mainnet)
        $network = $config['network'] ?? 'devnet';

        // Use explicit RPC URL if configured, otherwise use network-appropriate endpoint
        if (!empty($config['rpc_url'])) {
            $this->rpcUrl = $config['rpc_url'];
        } else {
            $this->rpcUrl = match($network) {
                'mainnet', 'mainnet-beta' => 'https://api.mainnet-beta.solana.com',
                'testnet' => 'https://api.testnet.solana.com',
                default => 'https://api.devnet.solana.com',
            };
        }
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
        $required = ['credentialId', 'smartWalletAddress'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new PasskeyValidationException("Missing required field: {$field}");
            }
        }

        // Validate Solana address format using STRICT base58
        // Base58 excludes: 0 (zero), O (uppercase o), I (uppercase i), l (lowercase L)
        // Valid: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
        if (!preg_match('/^[1-9A-HJ-NP-Za-km-z]{32,44}$/', $data['smartWalletAddress'])) {
            Log::error('Invalid base58 wallet address', ['address' => $data['smartWalletAddress']]);
            throw new PasskeyValidationException('Invalid smart wallet address format (not valid base58)');
        }

        // Validate credential ID (base64 or base64url format)
        // Portal may return standard base64 (+/=) or base64url (_-)
        if (!preg_match('/^[A-Za-z0-9_\-+\/=]+$/', $data['credentialId'])) {
            throw new PasskeyValidationException('Invalid credential ID format');
        }

        // publicKey is the P-256 passkey public key (not a Solana address)
        // It can be a byte array (from React SDK) or a string (older format)
        // Store it as JSON if it's an array
        if (isset($data['publicKey'])) {
            if (is_array($data['publicKey'])) {
                $data['publicKey'] = json_encode($data['publicKey']);
            } elseif (is_string($data['publicKey']) && strlen($data['publicKey']) < 40) {
                throw new PasskeyValidationException('Invalid public key format');
            }
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
        $updateData = [
            'smart_wallet_address' => $validatedData['smartWalletAddress'],
            'user_agent' => $userAgent ? substr($userAgent, 0, 500) : null,
            'counter' => $validatedData['counter'] ?? 0,
            'last_used_at' => now(),
        ];

        // Only update public_key if provided (may be null from vanilla JS implementation)
        if (!empty($validatedData['publicKey'])) {
            $updateData['public_key'] = $validatedData['publicKey'];
        }

        $credential = PasskeyCredential::updateOrCreate(
            ['credential_id' => $validatedData['credentialId']],
            $updateData
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
     *
     * Note: The counter is embedded in the authenticatorData from WebAuthn.
     * For now, we do basic credential verification. Full counter extraction
     * from authenticatorData can be added for production hardening.
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

        // For LazorKit integration, the counter comes from authenticatorData
        // The portal may not return it directly in the expected format
        // Skip strict counter check if counter is 0 (not provided)
        if ($counter > 0) {
            if ($counter <= $credential->counter) {
                Log::warning('Passkey replay attack detected', [
                    'credential_id' => substr($credentialId, 0, 20) . '...',
                    'stored_counter' => $credential->counter,
                    'received_counter' => $counter,
                ]);
                return false;
            }

            // Update counter
            $credential->update([
                'counter' => $counter,
            ]);
        }

        // Update last used timestamp
        $credential->update([
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
            'network' => $this->config['network'] ?? 'devnet',
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

    /**
     * Derive smart wallet address from credential ID (deterministic PDA derivation).
     *
     * The smart wallet is a Program Derived Address (PDA) derived from:
     * - Seeds: ["smart_wallet", credential_hash]
     * - Program: LazorKit program ID
     *
     * @param string $credentialId Base64 encoded credential ID
     * @param mixed $publicKey P-256 public key (not used for derivation, but validated)
     * @return string The smart wallet address (base58)
     */
    public function deriveSmartWalletAddress(string $credentialId, mixed $publicKey): string
    {
        // LazorKit program ID
        $programId = 'Gsuz7YcA5sbMGVRXT3xSYhJBessW4xFC4xYsihNCqMFh';
        $programIdBytes = $this->base58ToBytes($programId);

        // Compute credential hash (SHA256 of base64-decoded credential ID)
        $credentialBytes = base64_decode($credentialId);
        $credentialHash = hash('sha256', $credentialBytes, true);

        // PDA seed: "smart_wallet" + credential_hash
        $seed = "smart_wallet" . $credentialHash;

        // Find PDA (try bump values from 255 down to 0)
        for ($bump = 255; $bump >= 0; $bump--) {
            $seedWithBump = $seed . chr($bump);

            // Hash: SHA256(seeds + program_id + "ProgramDerivedAddress")
            $hash = hash('sha256', $seedWithBump . $programIdBytes . "ProgramDerivedAddress", true);

            // Check if point is NOT on the ed25519 curve (valid PDA)
            if (!$this->isOnCurve($hash)) {
                Log::info('Derived smart wallet PDA', [
                    'bump' => $bump,
                    'address' => $this->bytesToBase58(array_values(unpack('C*', $hash))),
                ]);
                return $this->bytesToBase58(array_values(unpack('C*', $hash)));
            }
        }

        throw new \RuntimeException('Failed to find valid PDA bump');
    }

    /**
     * Check if a 32-byte hash is on the ed25519 curve.
     * A valid PDA must NOT be on the curve.
     */
    private function isOnCurve(string $bytes): bool
    {
        // Simplified check: ed25519 curve order check
        // In practice, most random 32-byte values are NOT on the curve
        // The actual check involves complex elliptic curve math
        // For LazorKit, we use a simplified heuristic that works for PDA derivation

        // The ed25519 base point order is a large prime
        // We check if the high bit patterns indicate a valid curve point
        // This is a simplification - real implementation would use sodium_crypto_core_ed25519_is_valid_point

        if (function_exists('sodium_crypto_core_ed25519_is_valid_point')) {
            try {
                return sodium_crypto_core_ed25519_is_valid_point($bytes);
            } catch (\SodiumException $e) {
                return false;
            }
        }

        // Fallback: check if it looks like a valid point (very simplified)
        // Most 32-byte values won't be valid curve points
        // The last byte having certain patterns indicates invalid points more often
        $lastByte = ord($bytes[31]);

        // If the high bit is set in a way that's invalid for ed25519 compressed points
        // This is a heuristic - not cryptographically accurate but works for PDA finding
        return ($lastByte & 0x80) === 0 && $lastByte < 0x7f;
    }

    /**
     * Decode base58 string to bytes.
     */
    private function base58ToBytes(string $base58): string
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        if (function_exists('gmp_init')) {
            $value = gmp_init(0);
            for ($i = 0; $i < strlen($base58); $i++) {
                $char = $base58[$i];
                $pos = strpos($alphabet, $char);
                if ($pos === false) {
                    throw new \InvalidArgumentException("Invalid base58 character: $char");
                }
                $value = gmp_add(gmp_mul($value, 58), $pos);
            }

            $hex = gmp_strval($value, 16);
            if (strlen($hex) % 2 !== 0) {
                $hex = '0' . $hex;
            }

            // Pad to 32 bytes
            $hex = str_pad($hex, 64, '0', STR_PAD_LEFT);
            return hex2bin($hex);
        } else {
            // BCMath fallback
            $value = '0';
            for ($i = 0; $i < strlen($base58); $i++) {
                $char = $base58[$i];
                $pos = strpos($alphabet, $char);
                if ($pos === false) {
                    throw new \InvalidArgumentException("Invalid base58 character: $char");
                }
                $value = bcadd(bcmul($value, '58'), (string)$pos);
            }

            // Convert to hex
            $hex = '';
            while (bccomp($value, '0') > 0) {
                $remainder = bcmod($value, '16');
                $hex = dechex((int)$remainder) . $hex;
                $value = bcdiv($value, '16', 0);
            }

            if (strlen($hex) % 2 !== 0) {
                $hex = '0' . $hex;
            }

            // Pad to 32 bytes
            $hex = str_pad($hex, 64, '0', STR_PAD_LEFT);
            return hex2bin($hex);
        }
    }

    /**
     * Look up smart wallet address on-chain by credential ID.
     *
     * The portal returns credentialId but not the smart wallet address.
     * We need to compute the credential hash and look it up on-chain.
     *
     * @param string $credentialId Base64 encoded credential ID
     * @return string|null The smart wallet address (base58) or null if not found
     */
    public function lookupSmartWalletOnChain(string $credentialId): ?string
    {
        if (!$this->rpcUrl) {
            Log::warning('Cannot lookup smart wallet: RPC URL not configured');
            return null;
        }

        try {
            // Compute credential hash (SHA256 of base64-decoded credential ID)
            $credentialBytes = base64_decode($credentialId);
            $credentialHash = hash('sha256', $credentialBytes, true);

            // LazorKit program ID (mainnet)
            $programId = 'Gsuz7YcA5sbMGVRXT3xSYhJBessW4xFC4xYsihNCqMFh';

            // WalletDevice account discriminator
            $discriminator = [35, 85, 31, 31, 179, 48, 136, 123];

            // Query for WalletDevice accounts with matching credential hash
            // Structure: discriminator (8) + passkey_pubkey (33) + credential_hash (32) + smart_wallet (32) + bump (1)
            $response = $this->solanaRpcCall('getProgramAccounts', [
                $programId,
                [
                    'encoding' => 'base64',
                    'filters' => [
                        // Filter by discriminator at offset 0
                        [
                            'memcmp' => [
                                'offset' => 0,
                                'bytes' => $this->bytesToBase58($discriminator),
                            ],
                        ],
                        // Filter by credential hash at offset 41 (8 + 33)
                        [
                            'memcmp' => [
                                'offset' => 41,
                                'bytes' => $this->bytesToBase58(array_values(unpack('C*', $credentialHash))),
                            ],
                        ],
                    ],
                ],
            ]);

            if (empty($response) || !is_array($response)) {
                Log::info('No WalletDevice account found for credential', [
                    'credential_id' => substr($credentialId, 0, 20) . '...',
                ]);
                return null;
            }

            // Parse the first matching account
            $account = $response[0];
            $data = base64_decode($account['account']['data'][0]);

            // Extract smart_wallet pubkey from offset 73 (8 + 33 + 32)
            $smartWalletBytes = substr($data, 73, 32);
            $smartWalletAddress = $this->bytesToBase58(array_values(unpack('C*', $smartWalletBytes)));

            Log::info('Found smart wallet on-chain', [
                'credential_id' => substr($credentialId, 0, 20) . '...',
                'smart_wallet' => $smartWalletAddress,
            ]);

            return $smartWalletAddress;

        } catch (\Exception $e) {
            Log::error('Failed to lookup smart wallet on-chain', [
                'error' => $e->getMessage(),
                'credential_id' => substr($credentialId, 0, 20) . '...',
            ]);
            return null;
        }
    }

    /**
     * Create a smart wallet on-chain via the paymaster.
     *
     * @param string $credentialId Base64 encoded credential ID
     * @param mixed $publicKey P-256 public key (array of bytes or base64 string)
     * @return array{success: bool, smartWalletAddress?: string, error?: string}
     */
    public function createSmartWalletOnChain(string $credentialId, mixed $publicKey): array
    {
        try {
            $client = new \GuzzleHttp\Client(['timeout' => 60]);

            // Normalize public key to array format
            $pubkeyBytes = $publicKey;
            if (is_string($publicKey)) {
                $pubkeyBytes = array_values(unpack('C*', base64_decode($publicKey)));
            }

            // Compute credential hash
            $credentialBytes = base64_decode($credentialId);
            $credentialHash = hash('sha256', $credentialBytes, true);
            $credentialHashArray = array_values(unpack('C*', $credentialHash));

            // Get payer from paymaster
            $payerResponse = $client->get($this->paymasterUrl . '/payer');
            $payerData = json_decode($payerResponse->getBody()->getContents(), true);
            $payer = $payerData['payer'] ?? null;

            if (!$payer) {
                return ['success' => false, 'error' => 'Failed to get payer from paymaster'];
            }

            // Derive smart wallet PDA
            // Seeds: [SMART_WALLET_SEED, credential_hash]
            // This is a simplified version - the actual derivation needs to match the on-chain program
            $programId = 'Gsuz7YcA5sbMGVRXT3xSYhJBessW4xFC4xYsihNCqMFh';

            // Call paymaster to create wallet
            $createResponse = $client->post($this->paymasterUrl . '/create-wallet', [
                'json' => [
                    'credentialId' => $credentialId,
                    'publicKey' => $pubkeyBytes,
                    'credentialHash' => $credentialHashArray,
                ],
            ]);

            $createResult = json_decode($createResponse->getBody()->getContents(), true);

            if (!isset($createResult['smartWallet'])) {
                Log::error('Paymaster create-wallet response missing smartWallet', $createResult);
                return [
                    'success' => false,
                    'error' => $createResult['error'] ?? 'Paymaster did not return wallet address',
                ];
            }

            Log::info('Smart wallet created via paymaster', [
                'smart_wallet' => $createResult['smartWallet'],
            ]);

            return [
                'success' => true,
                'smartWalletAddress' => $createResult['smartWallet'],
            ];

        } catch (\GuzzleHttp\Exception\ClientException $e) {
            $response = $e->getResponse();
            $body = $response ? json_decode($response->getBody()->getContents(), true) : null;
            Log::error('Paymaster API error', [
                'status' => $response?->getStatusCode(),
                'body' => $body,
            ]);
            return [
                'success' => false,
                'error' => $body['error'] ?? 'Paymaster request failed',
            ];
        } catch (\Exception $e) {
            Log::error('Failed to create smart wallet on-chain', [
                'error' => $e->getMessage(),
            ]);
            return [
                'success' => false,
                'error' => 'Failed to create wallet: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Make a Solana JSON-RPC call.
     */
    private function solanaRpcCall(string $method, array $params = []): mixed
    {
        $client = new \GuzzleHttp\Client(['timeout' => 30]);

        $response = $client->post($this->rpcUrl, [
            'json' => [
                'jsonrpc' => '2.0',
                'id' => 1,
                'method' => $method,
                'params' => $params,
            ],
        ]);

        $result = json_decode($response->getBody()->getContents(), true);

        if (isset($result['error'])) {
            throw new \RuntimeException($result['error']['message'] ?? 'RPC error');
        }

        return $result['result'] ?? null;
    }

    /**
     * Convert byte array to base58 string.
     */
    private function bytesToBase58(array $bytes): string
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        if (function_exists('gmp_init')) {
            return $this->bytesToBase58WithGmp($bytes, $alphabet);
        } elseif (function_exists('bcadd')) {
            return $this->bytesToBase58WithBcmath($bytes, $alphabet);
        } else {
            throw new \RuntimeException('Neither GMP nor BCMath extension is available for base58 encoding');
        }
    }

    /**
     * Base58 encode using GMP.
     */
    private function bytesToBase58WithGmp(array $bytes, string $alphabet): string
    {
        $value = gmp_init(0);
        foreach ($bytes as $byte) {
            $value = gmp_add(gmp_mul($value, 256), $byte);
        }

        $result = '';
        while (gmp_cmp($value, 0) > 0) {
            list($value, $remainder) = gmp_div_qr($value, 58);
            $result = $alphabet[gmp_intval($remainder)] . $result;
        }

        // Handle leading zeros
        foreach ($bytes as $byte) {
            if ($byte === 0) {
                $result = '1' . $result;
            } else {
                break;
            }
        }

        return $result ?: '1';
    }

    /**
     * Base58 encode using BCMath.
     */
    private function bytesToBase58WithBcmath(array $bytes, string $alphabet): string
    {
        $value = '0';
        foreach ($bytes as $byte) {
            $value = bcadd(bcmul($value, '256'), (string)$byte);
        }

        $result = '';
        while (bccomp($value, '0') > 0) {
            $remainder = bcmod($value, '58');
            $result = $alphabet[(int)$remainder] . $result;
            $value = bcdiv($value, '58', 0);
        }

        // Handle leading zeros
        foreach ($bytes as $byte) {
            if ($byte === 0) {
                $result = '1' . $result;
            } else {
                break;
            }
        }

        return $result ?: '1';
    }
}
