<?php

namespace Lazorkit\Laravel\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Lazorkit\Laravel\Models\PasskeyCredential;

class PasskeyWalletCreated
{
    use Dispatchable, SerializesModels;

    /**
     * The passkey credential that was created.
     */
    public PasskeyCredential $credential;

    /**
     * Create a new event instance.
     */
    public function __construct(PasskeyCredential $credential)
    {
        $this->credential = $credential;
    }
}
