/**
 * LazorKit Wallet Manager
 * Vanilla JavaScript module for passkey-based Solana wallet authentication
 *
 * Uses popup-based communication with the LazorKit portal for WebAuthn ceremonies.
 * Compatible with any JavaScript framework or vanilla JS applications.
 */

class LazorkitWalletManager {
    constructor() {
        this.isInitialized = false;
        this.walletAddress = null;
        this.credentialId = null;
        this.config = null;
        this.popup = null;
        this.messageHandler = null;
    }

    /**
     * Initialize the LazorKit wallet manager
     * @param {Object} config - Configuration options
     * @param {string} config.portalUrl - LazorKit portal URL
     * @param {string} config.paymasterUrl - LazorKit paymaster URL
     * @param {string} config.rpcUrl - Solana RPC URL
     * @param {string[]} config.allowedOrigins - Allowed origins for postMessage
     */
    async initialize(config = {}) {
        if (this.isInitialized) return;

        // Fetch config from backend if not provided
        if (!config.portalUrl) {
            try {
                const response = await fetch('/api/lazorkit/config');
                if (response.ok) {
                    const backendConfig = await response.json();
                    config = { ...backendConfig, ...config };
                }
            } catch (error) {
                console.error('Failed to fetch LazorKit config:', error);
            }
        }

        this.config = {
            portalUrl: config.portalUrl || 'https://portal.lazor.sh',
            paymasterUrl: config.paymasterUrl || 'https://kora.devnet.lazorkit.com',
            rpcUrl: config.rpcUrl || null,
            allowedOrigins: config.allowedOrigins || ['https://portal.lazor.sh'],
        };

        // Restore session from localStorage
        this.restoreSession();

        this.isInitialized = true;
        console.log('LazorKit wallet manager initialized');
    }

    /**
     * Restore session from localStorage
     */
    restoreSession() {
        try {
            const authData = localStorage.getItem('lazorkit_auth');
            if (authData) {
                const parsed = JSON.parse(authData);
                // Check if session is not too old (24 hours)
                if (parsed.timestamp && (Date.now() - parsed.timestamp) < 86400000) {
                    this.walletAddress = parsed.wallet_address;
                    this.credentialId = parsed.credential_id;
                    console.log('Restored LazorKit session:', this.walletAddress);
                } else {
                    localStorage.removeItem('lazorkit_auth');
                }
            }
        } catch (error) {
            console.error('Failed to restore LazorKit session:', error);
            localStorage.removeItem('lazorkit_auth');
        }
    }

    /**
     * Connect via passkey (opens portal popup)
     * @returns {Promise<Object>} Connection result
     */
    async connect() {
        if (!this.isInitialized) {
            await this.initialize();
        }

        if (!this.isAvailable()) {
            throw new Error('WebAuthn is not supported in this browser');
        }

        return new Promise((resolve, reject) => {
            // Build portal URL with parameters
            const params = new URLSearchParams({
                action: 'connect',
                origin: window.location.origin,
                timestamp: Date.now().toString(),
                nonce: this.generateNonce(),
            });

            const portalUrl = `${this.config.portalUrl}?${params.toString()}`;

            // Open popup window
            const width = 420;
            const height = 600;
            const left = (window.screen.width - width) / 2 + (window.screenLeft || 0);
            const top = (window.screen.height - height) / 2 + (window.screenTop || 0);

            this.popup = window.open(
                portalUrl,
                'lazorkit-portal',
                `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no,scrollbars=yes,resizable=yes`
            );

            if (!this.popup) {
                reject(new Error('Popup blocked. Please allow popups and try again.'));
                return;
            }

            // Set up message handler
            this.messageHandler = (event) => {
                // Verify origin
                if (!this.config.allowedOrigins.includes(event.origin)) {
                    return;
                }

                const data = event.data;

                if (data.type === 'lazorkit:connect:success') {
                    this.handleConnectSuccess(data, resolve, reject);
                } else if (data.type === 'lazorkit:connect:error') {
                    this.handleConnectError(data, reject);
                } else if (data.type === 'lazorkit:connect:cancel') {
                    this.handleConnectCancel(reject);
                }
            };

            window.addEventListener('message', this.messageHandler);

            // Check popup status periodically
            const checkInterval = setInterval(() => {
                if (this.popup && this.popup.closed) {
                    clearInterval(checkInterval);
                    this.cleanup();
                    // Give time for message to arrive
                    setTimeout(() => {
                        if (!this.walletAddress) {
                            reject(new Error('Authentication cancelled'));
                        }
                    }, 500);
                }
            }, 500);

            // Timeout after 5 minutes
            setTimeout(() => {
                clearInterval(checkInterval);
                this.cleanup();
                if (!this.walletAddress) {
                    reject(new Error('Authentication timeout'));
                }
            }, 300000);
        });
    }

    /**
     * Handle successful connection from portal
     */
    async handleConnectSuccess(data, resolve, reject) {
        this.cleanup();

        try {
            // Validate required fields
            if (!data.credentialId || !data.smartWalletAddress || !data.publicKey) {
                throw new Error('Invalid response from portal');
            }

            // Authenticate with backend
            const response = await fetch('/api/lazorkit/auth/connect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': this.getCsrfToken(),
                },
                body: JSON.stringify({
                    credentialId: data.credentialId,
                    smartWalletAddress: data.smartWalletAddress,
                    publicKey: data.publicKey,
                    counter: data.counter || 0,
                }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Authentication failed');
            }

            const result = await response.json();

            // Store locally
            this.walletAddress = result.wallet_address;
            this.credentialId = data.credentialId;

            // Persist to localStorage
            localStorage.setItem('lazorkit_auth', JSON.stringify({
                wallet_address: this.walletAddress,
                credential_id: this.credentialId,
                timestamp: Date.now(),
            }));

            resolve({
                success: true,
                walletAddress: this.walletAddress,
                authMethod: 'passkey',
            });

        } catch (error) {
            console.error('Backend authentication failed:', error);
            reject(error);
        }
    }

    /**
     * Handle connection error from portal
     */
    handleConnectError(data, reject) {
        this.cleanup();
        reject(new Error(data.error || 'Authentication failed'));
    }

    /**
     * Handle connection cancellation
     */
    handleConnectCancel(reject) {
        this.cleanup();
        reject(new Error('Authentication cancelled by user'));
    }

    /**
     * Sign and send a transaction
     * @param {Object} transactionData - Transaction data
     * @returns {Promise<Object>} Transaction result
     */
    async signAndSendTransaction(transactionData) {
        if (!this.isConnected()) {
            throw new Error('Wallet not connected');
        }

        return new Promise(async (resolve, reject) => {
            try {
                // Prepare transaction on backend
                const prepareResponse = await fetch('/api/lazorkit/transaction/prepare', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': this.getCsrfToken(),
                    },
                    body: JSON.stringify(transactionData),
                });

                if (!prepareResponse.ok) {
                    const errorData = await prepareResponse.json();
                    throw new Error(errorData.error || 'Failed to prepare transaction');
                }

                const prepared = await prepareResponse.json();

                // Open portal for signing
                const params = new URLSearchParams({
                    action: 'sign',
                    transaction: JSON.stringify(prepared.transaction),
                    origin: window.location.origin,
                    nonce: this.generateNonce(),
                });

                const portalUrl = `${this.config.portalUrl}?${params.toString()}`;

                const width = 420;
                const height = 600;
                const left = (window.screen.width - width) / 2 + (window.screenLeft || 0);
                const top = (window.screen.height - height) / 2 + (window.screenTop || 0);

                this.popup = window.open(
                    portalUrl,
                    'lazorkit-sign',
                    `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no,scrollbars=yes,resizable=yes`
                );

                if (!this.popup) {
                    reject(new Error('Popup blocked'));
                    return;
                }

                // Set up message handler for signing
                const signHandler = async (event) => {
                    if (!this.config.allowedOrigins.includes(event.origin)) {
                        return;
                    }

                    const data = event.data;

                    if (data.type === 'lazorkit:sign:success') {
                        window.removeEventListener('message', signHandler);
                        if (this.popup && !this.popup.closed) {
                            this.popup.close();
                        }

                        // Submit signed transaction
                        try {
                            const submitResponse = await fetch('/api/lazorkit/transaction/submit', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-CSRF-TOKEN': this.getCsrfToken(),
                                },
                                body: JSON.stringify({
                                    serializedTransaction: data.serializedTransaction,
                                    signature: data.signature,
                                    counter: data.counter,
                                }),
                            });

                            const result = await submitResponse.json();

                            if (result.success) {
                                resolve({
                                    success: true,
                                    signature: result.signature,
                                    gasless: result.gasless || false,
                                });
                            } else {
                                reject(new Error(result.error || 'Transaction failed'));
                            }
                        } catch (error) {
                            reject(error);
                        }

                    } else if (data.type === 'lazorkit:sign:error') {
                        window.removeEventListener('message', signHandler);
                        if (this.popup && !this.popup.closed) {
                            this.popup.close();
                        }
                        reject(new Error(data.error || 'Signing failed'));
                    } else if (data.type === 'lazorkit:sign:cancel') {
                        window.removeEventListener('message', signHandler);
                        if (this.popup && !this.popup.closed) {
                            this.popup.close();
                        }
                        reject(new Error('Signing cancelled by user'));
                    }
                };

                window.addEventListener('message', signHandler);

                // Check popup status
                const checkInterval = setInterval(() => {
                    if (this.popup && this.popup.closed) {
                        clearInterval(checkInterval);
                        window.removeEventListener('message', signHandler);
                        setTimeout(() => {
                            reject(new Error('Signing cancelled'));
                        }, 500);
                    }
                }, 500);

                // Timeout after 5 minutes
                setTimeout(() => {
                    clearInterval(checkInterval);
                    window.removeEventListener('message', signHandler);
                    if (this.popup && !this.popup.closed) {
                        this.popup.close();
                    }
                    reject(new Error('Signing timeout'));
                }, 300000);

            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Disconnect wallet
     */
    async disconnect() {
        try {
            await fetch('/api/lazorkit/auth/disconnect', {
                method: 'POST',
                headers: {
                    'X-CSRF-TOKEN': this.getCsrfToken(),
                },
            });
        } catch (error) {
            console.error('Disconnect error:', error);
        }

        this.walletAddress = null;
        this.credentialId = null;
        localStorage.removeItem('lazorkit_auth');
    }

    /**
     * Check authentication status with backend
     * @returns {Promise<Object>} Status result
     */
    async checkAuthStatus() {
        try {
            const response = await fetch('/api/lazorkit/auth/status');
            const data = await response.json();

            if (data.authenticated) {
                this.walletAddress = data.wallet_address;
                return {
                    authenticated: true,
                    walletAddress: data.wallet_address,
                    authMethod: 'passkey',
                };
            }

            // Clear local state if not authenticated on backend
            this.walletAddress = null;
            this.credentialId = null;
            localStorage.removeItem('lazorkit_auth');

            return { authenticated: false };
        } catch (error) {
            console.error('Failed to check auth status:', error);
            return { authenticated: false };
        }
    }

    /**
     * Check if wallet is connected
     * @returns {boolean}
     */
    isConnected() {
        return this.walletAddress !== null && this.credentialId !== null;
    }

    /**
     * Get wallet address
     * @returns {string|null}
     */
    getWalletAddress() {
        return this.walletAddress;
    }

    /**
     * Check if WebAuthn/Passkey is available in this browser
     * @returns {boolean}
     */
    isAvailable() {
        return typeof window !== 'undefined' &&
               window.PublicKeyCredential !== undefined &&
               typeof window.PublicKeyCredential === 'function';
    }

    /**
     * Check if passkey authentication is enabled
     * @returns {boolean}
     */
    isEnabled() {
        return this.config?.enabled !== false;
    }

    /**
     * Cleanup resources
     */
    cleanup() {
        if (this.messageHandler) {
            window.removeEventListener('message', this.messageHandler);
            this.messageHandler = null;
        }
        if (this.popup && !this.popup.closed) {
            this.popup.close();
        }
        this.popup = null;
    }

    /**
     * Generate a random nonce
     * @returns {string}
     */
    generateNonce() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Get CSRF token from meta tag
     * @returns {string}
     */
    getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    }

    /**
     * Format wallet address for display (truncated)
     * @param {string} address
     * @returns {string}
     */
    formatAddress(address) {
        if (!address) return '';
        return `${address.slice(0, 4)}...${address.slice(-4)}`;
    }

    /**
     * Get wallet balance in SOL
     * @returns {Promise<Object>} Balance info { lamports, sol, formatted }
     */
    async getBalance() {
        if (!this.isConnected()) {
            throw new Error('Wallet not connected');
        }

        try {
            const response = await fetch('/api/lazorkit/wallet/balance', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'X-CSRF-TOKEN': this.getCsrfToken(),
                },
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to fetch balance');
            }

            const data = await response.json();
            return {
                lamports: data.lamports || 0,
                sol: data.sol || 0,
                formatted: data.formatted || '0 SOL',
            };
        } catch (error) {
            console.error('Failed to get balance:', error);
            throw error;
        }
    }

    /**
     * Get receive address (just the wallet address for passkey wallets)
     * @returns {string} Wallet address
     */
    getReceiveAddress() {
        if (!this.isConnected()) {
            throw new Error('Wallet not connected');
        }
        return this.walletAddress;
    }

    /**
     * Send SOL to another wallet
     * @param {string} recipientAddress - Destination wallet address
     * @param {number} amount - Amount in SOL
     * @returns {Promise<Object>} Transaction result
     */
    async sendTransfer(recipientAddress, amount) {
        if (!this.isConnected()) {
            throw new Error('Wallet not connected');
        }

        if (!recipientAddress || recipientAddress.length < 32) {
            throw new Error('Invalid recipient address');
        }

        if (!amount || amount <= 0) {
            throw new Error('Amount must be greater than 0');
        }

        // Convert SOL to lamports
        const amountLamports = Math.floor(amount * 1_000_000_000);

        return this.signAndSendTransaction({
            instructions: [
                {
                    to: recipientAddress,
                    amount_lamports: amountLamports,
                }
            ],
            metadata: {
                type: 'transfer',
                message: `Send ${amount} SOL to ${this.formatAddress(recipientAddress)}`,
            }
        });
    }

    /**
     * Generate QR code data URL for receive address
     * @param {number} size - QR code size in pixels
     * @returns {Promise<string>} Data URL of QR code
     */
    async getReceiveQRCode(size = 200) {
        if (!this.isConnected()) {
            throw new Error('Wallet not connected');
        }

        try {
            const response = await fetch(`/api/lazorkit/wallet/qr?size=${size}`, {
                headers: {
                    'Accept': 'application/json',
                    'X-CSRF-TOKEN': this.getCsrfToken(),
                },
            });

            if (!response.ok) {
                throw new Error('Failed to generate QR code');
            }

            const data = await response.json();
            return data.qr_code;
        } catch (error) {
            console.error('Failed to generate QR code:', error);
            throw error;
        }
    }

    /**
     * Copy wallet address to clipboard
     * @returns {Promise<boolean>} Success status
     */
    async copyAddress() {
        if (!this.isConnected()) {
            throw new Error('Wallet not connected');
        }

        try {
            await navigator.clipboard.writeText(this.walletAddress);
            return true;
        } catch (error) {
            console.error('Failed to copy address:', error);
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = this.walletAddress;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                return true;
            } finally {
                document.body.removeChild(textArea);
            }
        }
    }
}

// Export singleton instance
const lazorkitWalletManager = new LazorkitWalletManager();

// Make globally available
if (typeof window !== 'undefined') {
    window.lazorkitWalletManager = lazorkitWalletManager;
}

// ES Module export
export default lazorkitWalletManager;
export { LazorkitWalletManager };
