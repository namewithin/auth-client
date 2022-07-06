<?php

namespace Supervisor\Auth\Middleware;

use Illuminate\Auth\Middleware\Authenticate as Middleware;

class AuthenticateAttempt extends Middleware
{
    protected function authenticate($request, array $guards)
    {
        if (empty($guards)) {
            $guards = [null];
        }

        foreach ($guards as $guard) {
            if ($this->auth->guard($guard)->check()) {
                return $this->auth->shouldUse($guard);
            }
        }
    }
}
