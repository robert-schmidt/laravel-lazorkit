<?php

namespace Lazorkit\Laravel\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Lazorkit\Laravel\Services\LazorkitService;
use Lazorkit\Laravel\Services\LazorkitWalletService;
use Lazorkit\Laravel\Exceptions\PasskeyValidationException;
use Lazorkit\Laravel\Exceptions\LazorkitException;

class LazorkitController extends Controller
{
    private LazorkitService $lazorkitService;
    private LazorkitWalletService $walletService;

    public function __construct(LazorkitService $lazorkitService, LazorkitWalletService $walletService)
    {
        $this->lazorkitService = $lazorkitService;
        $this->walletService = $walletService;
    }

    /**
     * Get LazorKit configuration for frontend.
     */
    public function getConfig(): JsonResponse
    {
        return response()->json($this->lazorkitService->getPortalConfig());
    }

    /**
     * Handle passkey connection from portal.
     */
    public function connect(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'credentialId' => 'required|string|max:255',
            'smartWalletAddress' => 'required|string|min:32|max:44',
            // publicKey is the P-256 passkey pubkey - can be string or array of bytes (optional from on-chain lookup)
            'publicKey' => 'nullable',
            // counter may not be available from on-chain lookup
            'counter' => 'nullable|integer|min:0',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'Invalid request data',
                'validation_errors' => $validator->errors(),
            ], 400);
        }

        try {
            // Validate the data from portal
            $validatedData = $this->lazorkitService->validatePortalResponse($request->all());

            // Create or update credential
            $credential = $this->lazorkitService->createOrUpdateCredential(
                $validatedData,
                $request->userAgent()
            );

            // Link to WalletUser if the model exists and has the trait
            $walletUserClass = config('lazorkit.wallet_user_model', \App\Models\WalletUser::class);
            if (class_exists($walletUserClass)) {
                $walletUser = $walletUserClass::firstOrCreate(
                    ['wallet_address' => $credential->smart_wallet_address],
                    [
                        'auth_method' => 'passkey',
                        'last_login' => now(),
                    ]
                );

                // Update last login for existing users
                if (!$walletUser->wasRecentlyCreated) {
                    $walletUser->update(['last_login' => now()]);
                }
            }

            // Store in session
            session([
                'wallet_address' => $credential->smart_wallet_address,
                'lazorkit_credential_id' => $credential->credential_id,
                'auth_method' => 'passkey',
            ]);

            Log::info('Passkey authentication successful', [
                'smart_wallet' => $credential->smart_wallet_address,
                'credential_id' => substr($credential->credential_id, 0, 20) . '...',
            ]);

            return response()->json([
                'success' => true,
                'wallet_address' => $credential->smart_wallet_address,
                'authenticated' => true,
                'auth_method' => 'passkey',
            ]);

        } catch (PasskeyValidationException $e) {
            Log::warning('Passkey validation failed', ['error' => $e->getMessage()]);
            return response()->json(['error' => $e->getMessage()], 400);
        } catch (\Exception $e) {
            Log::error('Passkey connection failed', ['error' => $e->getMessage()]);
            return response()->json(['error' => 'Authentication failed'], 500);
        }
    }

    /**
     * Disconnect passkey session.
     */
    public function disconnect(Request $request): JsonResponse
    {
        session()->forget(['wallet_address', 'lazorkit_credential_id', 'auth_method']);

        return response()->json(['success' => true]);
    }

    /**
     * Get current authentication status.
     */
    public function status(): JsonResponse
    {
        $walletAddress = session('wallet_address');
        $authMethod = session('auth_method');

        if (!$walletAddress || $authMethod !== 'passkey') {
            return response()->json([
                'authenticated' => false,
            ]);
        }

        return response()->json([
            'authenticated' => true,
            'wallet_address' => $walletAddress,
            'auth_method' => 'passkey',
        ]);
    }

    /**
     * Prepare a transaction for passkey signing.
     */
    public function prepareTransaction(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'instructions' => 'required|array',
            'instructions.*.to' => 'sometimes|string|min:32|max:44',
            'instructions.*.amount_lamports' => 'sometimes|integer|min:0',
            'metadata' => 'nullable|array',
            'metadata.message' => 'nullable|string|max:500',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'Invalid transaction data',
                'validation_errors' => $validator->errors(),
            ], 400);
        }

        $walletAddress = session('wallet_address');
        $authMethod = session('auth_method');

        if (!$walletAddress || $authMethod !== 'passkey') {
            return response()->json(['error' => 'Not authenticated'], 401);
        }

        try {
            $prepared = $this->walletService->prepareTransaction(
                $request->all(),
                $walletAddress
            );

            return response()->json([
                'success' => true,
                'transaction' => $prepared,
            ]);
        } catch (LazorkitException $e) {
            Log::error('Transaction preparation failed', ['error' => $e->getMessage()]);
            return response()->json(['error' => $e->getMessage()], 400);
        } catch (\Exception $e) {
            Log::error('Transaction preparation failed', ['error' => $e->getMessage()]);
            return response()->json(['error' => 'Failed to prepare transaction'], 500);
        }
    }

    /**
     * Submit a signed transaction.
     */
    public function submitTransaction(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'serializedTransaction' => 'required|string',
            'signature' => 'required|string',
            'counter' => 'required|integer|min:0',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'Invalid submission data',
                'validation_errors' => $validator->errors(),
            ], 400);
        }

        $walletAddress = session('wallet_address');
        $credentialId = session('lazorkit_credential_id');

        if (!$walletAddress || !$credentialId) {
            return response()->json(['error' => 'Not authenticated'], 401);
        }

        // Verify credential counter (replay protection)
        if (!$this->lazorkitService->verifyCredential($credentialId, $request->counter)) {
            return response()->json(['error' => 'Invalid credential or replay detected'], 403);
        }

        try {
            $result = $this->walletService->submitSignedTransaction([
                'serializedTransaction' => $request->serializedTransaction,
                'signature' => $request->signature,
                'smartWalletAddress' => $walletAddress,
            ]);

            if ($result['success']) {
                return response()->json([
                    'success' => true,
                    'signature' => $result['signature'],
                    'gasless' => $result['gasless'] ?? false,
                ]);
            }

            return response()->json([
                'error' => $result['error'] ?? 'Transaction failed',
            ], 400);

        } catch (LazorkitException $e) {
            Log::error('Transaction submission failed', ['error' => $e->getMessage()]);
            return response()->json(['error' => $e->getMessage()], 400);
        } catch (\Exception $e) {
            Log::error('Transaction submission failed', ['error' => $e->getMessage()]);
            return response()->json(['error' => 'Submission failed'], 500);
        }
    }

    /**
     * Get transaction status.
     */
    public function getTransactionStatus(string $signature): JsonResponse
    {
        $status = $this->walletService->getTransactionStatus($signature);

        if (!$status) {
            return response()->json([
                'found' => false,
            ]);
        }

        return response()->json([
            'found' => true,
            'status' => $status,
        ]);
    }

    /**
     * Get wallet balance.
     */
    public function getBalance(): JsonResponse
    {
        $walletAddress = session('wallet_address');
        $authMethod = session('auth_method');

        if (!$walletAddress) {
            return response()->json(['error' => 'Not authenticated'], 401);
        }

        try {
            $balance = $this->walletService->getBalance($walletAddress);

            return response()->json([
                'success' => true,
                'lamports' => $balance['lamports'],
                'sol' => $balance['sol'],
                'formatted' => $balance['formatted'],
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to get balance', ['error' => $e->getMessage()]);
            // Return a graceful response with null balance instead of 500
            return response()->json([
                'success' => false,
                'lamports' => null,
                'sol' => null,
                'formatted' => null,
                'error' => 'Unable to fetch balance. RPC may be rate limited.',
            ]);
        }
    }

    /**
     * Get QR code for wallet address.
     */
    public function getQRCode(Request $request): JsonResponse
    {
        $walletAddress = session('wallet_address');

        if (!$walletAddress) {
            return response()->json(['error' => 'Not authenticated'], 401);
        }

        $size = (int) $request->input('size', 200);
        $size = min(max($size, 100), 400); // Clamp between 100-400

        try {
            $qrCode = $this->generateQRCodeUrl($walletAddress, $size);

            return response()->json([
                'success' => true,
                'wallet_address' => $walletAddress,
                'qr_code' => $qrCode,
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to generate QR code', ['error' => $e->getMessage()]);
            return response()->json(['error' => 'Failed to generate QR code'], 500);
        }
    }

    /**
     * Generate QR code URL using QR Server API.
     */
    private function generateQRCodeUrl(string $data, int $size): string
    {
        // Use QR Server API (free, no API key required)
        $encodedData = urlencode('solana:' . $data);
        return "https://api.qrserver.com/v1/create-qr-code/?size={$size}x{$size}&data={$encodedData}&format=png";
    }

    /**
     * Look up smart wallet address by credential ID.
     * Called after portal returns to resolve the actual Solana address.
     */
    public function lookupSmartWallet(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'credentialId' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'Invalid request',
                'validation_errors' => $validator->errors(),
            ], 400);
        }

        try {
            $smartWallet = $this->lazorkitService->lookupSmartWalletOnChain(
                $request->input('credentialId')
            );

            if (!$smartWallet) {
                return response()->json([
                    'success' => false,
                    'error' => 'Smart wallet not found on-chain. The wallet may need to be created first.',
                    'needs_creation' => true,
                ]);
            }

            return response()->json([
                'success' => true,
                'smartWalletAddress' => $smartWallet,
            ]);

        } catch (\Exception $e) {
            Log::error('Smart wallet lookup failed', ['error' => $e->getMessage()]);
            return response()->json([
                'error' => 'Failed to lookup smart wallet',
            ], 500);
        }
    }

    /**
     * Get wallet info (address, balance, etc.)
     */
    public function getWalletInfo(): JsonResponse
    {
        $walletAddress = session('wallet_address');
        $authMethod = session('auth_method');

        if (!$walletAddress || $authMethod !== 'passkey') {
            return response()->json(['error' => 'Not authenticated'], 401);
        }

        try {
            $balance = $this->walletService->getBalance($walletAddress);

            return response()->json([
                'success' => true,
                'wallet_address' => $walletAddress,
                'auth_method' => 'passkey',
                'balance' => [
                    'lamports' => $balance['lamports'],
                    'sol' => $balance['sol'],
                    'formatted' => $balance['formatted'],
                ],
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to get wallet info', ['error' => $e->getMessage()]);
            return response()->json([
                'success' => true,
                'wallet_address' => $walletAddress,
                'auth_method' => 'passkey',
                'balance' => null,
                'balance_error' => 'Failed to fetch balance',
            ]);
        }
    }
}
