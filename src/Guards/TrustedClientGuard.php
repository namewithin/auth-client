<?php

namespace Supervisor\Auth\Guards;

use Illuminate\Auth\GenericUser;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;

class TrustedClientGuard implements Guard
{
    use GuardHelpers;

    /**
     * The request instance.
     *
     * @var Request
     */
    protected $request;

    /**
     * Create a new request client guard instance.
     *
     * @param Request $request
     *
     * @return void
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Get the currently client.
     *
     * @return Authenticatable|null
     */
    public function user(): ?Authenticatable
    {
        $client = [];

        $client['id'] = $this->request->header('Auth-Client-Id');
        $client['name'] = $this->request->header('Auth-Client-Name');

        return Arr::has(array_filter($client), ['id', 'name']) ? new GenericUser((array) $client) : null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return false;
    }
}
