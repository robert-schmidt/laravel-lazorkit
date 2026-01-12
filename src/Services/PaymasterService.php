<?php

namespace Lazorkit\Laravel\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Lazorkit\Laravel\Exceptions\LazorkitException;

class PaymasterService
{
    private string $paymasterUrl;
    private int $timeout;

    public function __construct()
    {
        $this->paymasterUrl = config('lazorkit.paymaster_url', 'https://kora.devnet.lazorkit.com');
        $this->timeout = 30;
    }

    /**
     * Check if paymaster is available and enabled.
     */
    public function isAvailable(): bool
    {
        return !empty($this->paymasterUrl) && config('lazorkit.use_paymaster', true);
    }

    /**
     * Submit a signed transaction through the paymaster for gasless execution.
     *
     * LazorKit paymaster expects:
     * - message: The original transaction message (base64)
     * - signature: The secp256r1 signature from WebAuthn (base64)
     * - authenticatorData: The WebAuthn authenticator data (base64)
     * - credentialId: The credential ID used for signing
     */
    public function submitTransaction(array $signedTransaction): array
    {
        if (!$this->isAvailable()) {
            return [
                'success' => false,
                'error' => 'Paymaster not available',
                'fallback' => true,
            ];
        }

        try {
            // Format the request for LazorKit paymaster
            $payload = [
                'message' => $signedTransaction['serializedTransaction'],
                'signature' => $signedTransaction['signature'],
                'smartWallet' => $signedTransaction['smartWalletAddress'],
            ];

            // Add authenticator data if available
            if (!empty($signedTransaction['authenticatorData'])) {
                $payload['authenticatorData'] = $signedTransaction['authenticatorData'];
            }

            // Add credential ID if available
            if (!empty($signedTransaction['credentialId'])) {
                $payload['credentialId'] = $signedTransaction['credentialId'];
            }

            // Add signed payload if available (some paymaster versions need this)
            if (!empty($signedTransaction['signedPayload'])) {
                $payload['signedPayload'] = $signedTransaction['signedPayload'];
            }

            Log::info('Submitting to paymaster', [
                'url' => "{$this->paymasterUrl}/submit",
                'smartWallet' => $signedTransaction['smartWalletAddress'],
                'hasAuthData' => !empty($signedTransaction['authenticatorData']),
            ]);

            $response = Http::timeout($this->timeout)->post("{$this->paymasterUrl}/submit", $payload);

            if ($response->successful()) {
                $data = $response->json();

                Log::info('Paymaster transaction submitted successfully', [
                    'signature' => $data['txSignature'] ?? $data['signature'] ?? 'unknown',
                ]);

                return [
                    'success' => true,
                    'signature' => $data['txSignature'] ?? $data['signature'],
                    'gasless' => true,
                ];
            }

            Log::warning('Paymaster submission failed', [
                'status' => $response->status(),
                'response' => $response->body(),
            ]);

            // Try alternative paymaster endpoint format
            return $this->tryAlternativeSubmission($signedTransaction, $response->body());

        } catch (\Exception $e) {
            Log::error('Paymaster error', [
                'error' => $e->getMessage(),
            ]);

            return [
                'success' => false,
                'error' => $e->getMessage(),
                'fallback' => true,
            ];
        }
    }

    /**
     * Try alternative paymaster API format if the first one fails.
     */
    private function tryAlternativeSubmission(array $signedTransaction, string $previousError): array
    {
        try {
            // Some LazorKit paymaster versions use different endpoints/formats
            $response = Http::timeout($this->timeout)->post("{$this->paymasterUrl}/api/v1/submit", [
                'tx' => $signedTransaction['serializedTransaction'],
                'sig' => $signedTransaction['signature'],
                'authData' => $signedTransaction['authenticatorData'] ?? '',
                'wallet' => $signedTransaction['smartWalletAddress'],
            ]);

            if ($response->successful()) {
                $data = $response->json();
                return [
                    'success' => true,
                    'signature' => $data['txSignature'] ?? $data['signature'] ?? $data['result'],
                    'gasless' => true,
                ];
            }

            return [
                'success' => false,
                'error' => "Paymaster failed: {$previousError}",
                'fallback' => true,
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => "Paymaster failed: {$previousError}",
                'fallback' => true,
            ];
        }
    }

    /**
     * Estimate gas cost for a transaction.
     */
    public function estimateGas(array $transaction): ?int
    {
        if (!$this->isAvailable()) {
            return null;
        }

        try {
            $response = Http::timeout(10)->post("{$this->paymasterUrl}/estimate", [
                'transaction' => $transaction,
            ]);

            if ($response->successful()) {
                return $response->json()['estimatedGas'] ?? null;
            }

            return null;
        } catch (\Exception $e) {
            Log::warning('Gas estimation failed', ['error' => $e->getMessage()]);
            return null;
        }
    }

    /**
     * Check paymaster health/availability.
     */
    public function healthCheck(): bool
    {
        if (!$this->isAvailable()) {
            return false;
        }

        try {
            $response = Http::timeout(5)->get("{$this->paymasterUrl}/health");
            return $response->successful();
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get paymaster configuration.
     */
    public function getConfig(): array
    {
        return [
            'url' => $this->paymasterUrl,
            'enabled' => $this->isAvailable(),
            'timeout' => $this->timeout,
        ];
    }
}
