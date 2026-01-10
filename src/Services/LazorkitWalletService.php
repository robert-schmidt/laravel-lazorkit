<?php

namespace Lazorkit\Laravel\Services;

use Lazorkit\Laravel\Models\PasskeyCredential;
use Lazorkit\Laravel\Exceptions\LazorkitException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class LazorkitWalletService
{
    private LazorkitService $lazorkitService;
    private PaymasterService $paymasterService;

    public function __construct(LazorkitService $lazorkitService, PaymasterService $paymasterService)
    {
        $this->lazorkitService = $lazorkitService;
        $this->paymasterService = $paymasterService;
    }

    /**
     * Prepare a transaction for signing by the passkey.
     *
     * @throws LazorkitException
     */
    public function prepareTransaction(array $transactionData, string $smartWalletAddress): array
    {
        // Get the credential for this wallet
        $credential = $this->lazorkitService->getCredentialBySmartWallet($smartWalletAddress);

        if (!$credential) {
            throw new LazorkitException('No passkey credential found for this wallet');
        }

        // Build transaction instructions
        $instructions = [];
        foreach ($transactionData['instructions'] ?? [] as $instruction) {
            $instructions[] = [
                'programId' => $instruction['programId'] ?? '11111111111111111111111111111111', // System Program
                'keys' => $instruction['keys'] ?? [],
                'data' => $instruction['data'] ?? '',
            ];
        }

        // Generate unique nonce for this transaction
        $nonce = bin2hex(random_bytes(16));

        return [
            'smartWalletAddress' => $smartWalletAddress,
            'credentialId' => $credential->credential_id,
            'instructions' => $instructions,
            'message' => $transactionData['metadata']['message'] ?? 'HeisenBERT Transaction',
            'label' => $transactionData['metadata']['label'] ?? 'HeisenBERT',
            'timestamp' => now()->timestamp,
            'nonce' => $nonce,
            // Include transfer details if this is a transfer transaction
            'transfers' => $this->extractTransfers($transactionData),
        ];
    }

    /**
     * Extract transfer details from transaction data.
     */
    private function extractTransfers(array $transactionData): array
    {
        $transfers = [];

        foreach ($transactionData['instructions'] ?? [] as $instruction) {
            if (isset($instruction['to']) && isset($instruction['amount_lamports'])) {
                $transfers[] = [
                    'to' => $instruction['to'],
                    'amount_lamports' => (int) $instruction['amount_lamports'],
                    'memo' => $instruction['memo'] ?? null,
                ];
            }
        }

        return $transfers;
    }

    /**
     * Submit a signed transaction to the Solana network.
     *
     * @throws LazorkitException
     */
    public function submitSignedTransaction(array $signedTransaction): array
    {
        // Try paymaster first if available (gasless)
        if ($this->paymasterService->isAvailable()) {
            $result = $this->paymasterService->submitTransaction($signedTransaction);

            if ($result['success']) {
                return $result;
            }

            // If paymaster failed but we should fallback
            if (!$result['fallback']) {
                throw new LazorkitException($result['error'] ?? 'Paymaster submission failed');
            }

            Log::info('Paymaster fallback to direct submission');
        }

        // Fallback to direct submission
        return $this->submitDirect($signedTransaction);
    }

    /**
     * Submit transaction directly to Solana RPC.
     */
    private function submitDirect(array $signedTransaction): array
    {
        $rpcUrl = $this->lazorkitService->getRpcUrl() ?? config('solana.rpc_url');

        if (!$rpcUrl) {
            throw new LazorkitException('No RPC URL configured');
        }

        try {
            $response = Http::timeout(30)->post($rpcUrl, [
                'jsonrpc' => '2.0',
                'id' => 1,
                'method' => 'sendTransaction',
                'params' => [
                    $signedTransaction['serializedTransaction'],
                    [
                        'encoding' => 'base64',
                        'skipPreflight' => false,
                        'preflightCommitment' => 'confirmed',
                    ],
                ],
            ]);

            if ($response->failed()) {
                throw new LazorkitException('Transaction submission failed: ' . $response->body());
            }

            $result = $response->json();

            if (isset($result['error'])) {
                throw new LazorkitException('Transaction error: ' . ($result['error']['message'] ?? 'Unknown error'));
            }

            Log::info('Transaction submitted directly', [
                'signature' => $result['result'] ?? 'unknown',
            ]);

            return [
                'success' => true,
                'signature' => $result['result'],
                'gasless' => false,
            ];

        } catch (\Exception $e) {
            Log::error('Direct transaction submission failed', [
                'error' => $e->getMessage(),
            ]);

            throw new LazorkitException('Transaction submission failed: ' . $e->getMessage());
        }
    }

    /**
     * Get transaction status from Solana RPC.
     */
    public function getTransactionStatus(string $signature): ?array
    {
        $rpcUrl = $this->lazorkitService->getRpcUrl() ?? config('solana.rpc_url');

        if (!$rpcUrl) {
            return null;
        }

        try {
            $response = Http::post($rpcUrl, [
                'jsonrpc' => '2.0',
                'id' => 1,
                'method' => 'getTransaction',
                'params' => [
                    $signature,
                    ['encoding' => 'json', 'commitment' => 'confirmed'],
                ],
            ]);

            if ($response->successful()) {
                $data = $response->json();
                return $data['result'] ?? null;
            }

            return null;
        } catch (\Exception $e) {
            Log::warning('Failed to get transaction status', [
                'signature' => $signature,
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    /**
     * Build a SOL transfer transaction.
     */
    public function buildTransferTransaction(
        string $fromWallet,
        string $toWallet,
        int $amountLamports,
        ?string $memo = null
    ): array {
        $instructions = [
            [
                'programId' => '11111111111111111111111111111111', // System Program
                'to' => $toWallet,
                'amount_lamports' => $amountLamports,
            ],
        ];

        // Add memo if provided
        if ($memo) {
            $instructions[] = [
                'programId' => 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', // Memo Program
                'memo' => $memo,
            ];
        }

        return [
            'instructions' => $instructions,
            'metadata' => [
                'message' => 'SOL Transfer',
                'label' => 'HeisenBERT',
            ],
        ];
    }

    /**
     * Build a split payment transaction (for marketplace purchases).
     */
    public function buildSplitPaymentTransaction(
        string $buyerWallet,
        string $sellerWallet,
        string $platformWallet,
        int $sellerAmountLamports,
        int $platformAmountLamports,
        ?string $memo = null
    ): array {
        $instructions = [];

        // Payment to seller
        if ($sellerAmountLamports > 0) {
            $instructions[] = [
                'programId' => '11111111111111111111111111111111',
                'to' => $sellerWallet,
                'amount_lamports' => $sellerAmountLamports,
            ];
        }

        // Payment to platform
        if ($platformAmountLamports > 0) {
            $instructions[] = [
                'programId' => '11111111111111111111111111111111',
                'to' => $platformWallet,
                'amount_lamports' => $platformAmountLamports,
            ];
        }

        // Add memo if provided
        if ($memo) {
            $instructions[] = [
                'programId' => 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',
                'memo' => $memo,
            ];
        }

        return [
            'instructions' => $instructions,
            'metadata' => [
                'message' => 'HeisenBERT Purchase',
                'label' => 'HeisenBERT',
            ],
        ];
    }

    /**
     * Get wallet balance from Solana RPC.
     */
    public function getBalance(string $walletAddress): array
    {
        $rpcUrl = $this->getRpcUrl();

        if (!$rpcUrl) {
            throw new LazorkitException('No RPC URL configured');
        }

        try {
            $response = Http::timeout(10)->post($rpcUrl, [
                'jsonrpc' => '2.0',
                'id' => 1,
                'method' => 'getBalance',
                'params' => [
                    $walletAddress,
                    ['commitment' => 'confirmed'],
                ],
            ]);

            if ($response->failed()) {
                throw new LazorkitException('Failed to fetch balance: ' . $response->body());
            }

            $result = $response->json();

            if (isset($result['error'])) {
                throw new LazorkitException('RPC error: ' . ($result['error']['message'] ?? 'Unknown error'));
            }

            $lamports = $result['result']['value'] ?? 0;
            $sol = $lamports / 1_000_000_000; // Convert lamports to SOL

            return [
                'lamports' => $lamports,
                'sol' => $sol,
                'formatted' => number_format($sol, 4) . ' SOL',
            ];
        } catch (\Exception $e) {
            Log::error('Failed to get wallet balance', [
                'wallet' => $walletAddress,
                'error' => $e->getMessage(),
            ]);
            throw $e;
        }
    }

    /**
     * Get RPC URL for Solana network.
     */
    private function getRpcUrl(): ?string
    {
        // Check config for RPC URL
        $network = config('lazorkit.network', 'devnet');

        // Use public RPC endpoints based on network
        return match($network) {
            'mainnet', 'mainnet-beta' => 'https://api.mainnet-beta.solana.com',
            'testnet' => 'https://api.testnet.solana.com',
            default => 'https://api.devnet.solana.com',
        };
    }
}
