<?php

namespace Lazorkit\Laravel\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class PasskeyTransactionSigned
{
    use Dispatchable, SerializesModels;

    /**
     * The smart wallet address that signed.
     */
    public string $smartWalletAddress;

    /**
     * The transaction signature.
     */
    public string $signature;

    /**
     * Whether the transaction was gasless.
     */
    public bool $gasless;

    /**
     * Create a new event instance.
     */
    public function __construct(string $smartWalletAddress, string $signature, bool $gasless = false)
    {
        $this->smartWalletAddress = $smartWalletAddress;
        $this->signature = $signature;
        $this->gasless = $gasless;
    }
}
