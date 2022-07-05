<?php

namespace Supervisor\Auth;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\ResourceServer;
use Supervisor\Auth\Guards\ClientGuard;
use Supervisor\Auth\Guards\TrustedClientGuard;
use Laravel\Passport\ClientRepository;

class ServiceProvider extends IlluminateServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerGuard();
    }

    /**
     * Register the token guard.
     *
     * @return void
     */
    protected function registerGuard()
    {
        \Auth::extend('client', function ($app, $name, array $config) {
            return $this->makeGuard($config);
        });

        \Auth::extend('trusted.client', function ($app, $name, array $config) {
            return $this->makeTrustedClientGuard($config);
        });
    }

    /**
     * Make an instance of the token guard.
     *
     * @param  array $config
     * @return RequestGuard
     */
    protected function makeGuard(array $config)
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new ClientGuard(
                $request,
                $this->app->make(ResourceServer::class),
                \Auth::createUserProvider($config['provider']),
                $this->app->make(TokenRepository::class),
                $this->app->make(ClientRepository::class),
                $this->app->make('encrypter')
            ))->user();
        }, $this->app['request']);
    }

    /**
     * Make an instance of the token guard.
     *
     * @param  array $config
     * @return RequestGuard
     */
    protected function makeTrustedClientGuard(array $config)
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new TrustedClientGuard($request))->user();
        }, $this->app['request']);
    }
}
