<?php

namespace Lazorkit\Laravel\Exceptions;

use Exception;

class LazorkitException extends Exception
{
    /**
     * Create a new LazorkitException.
     */
    public function __construct(string $message = 'LazorKit operation failed', int $code = 0, ?Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
