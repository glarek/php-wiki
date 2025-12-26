<?php

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Exception\HttpForbiddenException;

class AdminMiddleware
{
    public function __invoke(Request $request, RequestHandler $handler): Response
    {
        $token = $request->getAttribute('token'); // 'token' attribute set by JwtAuth
        
        // Debugging: Check what we actually got
        $role = $token['role'] ?? 'guest';
        
        if (!$token || $role !== 'admin') {
            throw new HttpForbiddenException($request, "Unauthorized: Admin access required.");
        }

        return $handler->handle($request);
    }
}
