<?php

namespace Lazorkit\Laravel\Exceptions;

class PasskeyValidationException extends LazorkitException
{
    /**
     * Create a new PasskeyValidationException.
     */
    public function __construct(string $message = 'Passkey validation failed', int $code = 400)
    {
        parent::__construct($message, $code);
    }
}
