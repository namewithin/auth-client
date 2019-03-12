<?php

namespace PDFfiller\SupervisorAuth\Guards;

use Illuminate\Http\Request;
use Laravel\Passport\Guards\TokenGuard as PassportTokenGuard;
use Laravel\Passport\Passport;

class TokenGuard extends PassportTokenGuard
{

    /**
     * Get the user for the incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    public function user(Request $request)
    {
        if ($request->bearerToken()) {
            $user = $this->authenticateViaBearerToken($request);
        } elseif ($request->cookie(Passport::cookie())) {
            $user = $this->authenticateViaCookie($request);
        }

        $client = $this->client($request);

        if (!$this->clients->validateProvider($client, $user)) {
            return;
        }

        return $user;
    }
}
