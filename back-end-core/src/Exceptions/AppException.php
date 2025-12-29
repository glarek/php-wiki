<?php

namespace App\Exceptions;

use Exception;

class AppException extends Exception
{
    protected string $type;

    public function __construct(string $message, int $code = 400, string $type = 'UNKNOWN_ERROR')
    {
        parent::__construct($message, $code);
        $this->type = $type;
    }

    public function getType(): string
    {
        return $this->type;
    }
}
