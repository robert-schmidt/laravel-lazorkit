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
            $response = Http::timeout($this->timeout)->post("{$this->paymasterUrl}/submit", [
                'transaction' => $signedTransaction['serializedTransaction'],
                'signature' => $signedTransaction['signature'],
                'smartWallet' => $signedTransaction['smartWalletAddress'],
            ]);

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

            return [
                'success' => false,
                'error' => 'Paymaster request failed',
                'fallback' => true,
            ];

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
