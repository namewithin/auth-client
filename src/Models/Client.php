<?php

namespace PDFfiller\SupervisorAuth\Models;

use Illuminate\Database\Eloquent\Relations\HasOne;
use Laravel\Passport\Client as PassportClient;

class Client extends PassportClient
{
    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'grant_types' => 'array',
        'personal_access_client' => 'bool',
        'password_client' => 'bool',
        'revoked' => 'bool',
        'with_dummy_user' => 'bool',
    ];

    /**
     * Get the user that the client
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasOne
     */
    public function user(): HasOne
    {
        return $this->hasOne(config('auth.providers.'.config('auth.guards.client_user.provider').'.model'));
    }
}
