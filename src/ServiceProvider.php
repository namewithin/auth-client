<?php

namespace PDFfiller\SupervisorAuth;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider as IlluminateServiceProvider;
use PDFfiller\SupervisorAuth\Guards\TokenGuard;
use PDFfiller\SupervisorAuth\Repositories\ClientUser as UserRepository;
use PDFfiller\SupervisorAuth\Repositories\ClientRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\ResourceServer;
use PDFfiller\SupervisorAuth\Console\ClientCommand;
use PDFfiller\SupervisorAuth\Grants\ClientGrant;

class ServiceProvider extends IlluminateServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->commands([
            ClientCommand::class,
        ]);

        app(AuthorizationServer::class)->enableGrantType(
            $this->makeClientGrant(), Passport::tokensExpireIn()
        );

        $this->setAuthProvider();

        Passport::routes();
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerMigrations();

        $this->registerGuard();
    }

    /**
     * Register Passport's migration files.
     *
     * @return void
     */
    protected function registerMigrations()
    {
        if (Passport::$runsMigrations) {
            return $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        }
    }

    /**
     * Create and configure a Password grant instance.
     *
     * @return \League\OAuth2\Server\Grant\PasswordGrant
     */
    protected function makeClientGrant()
    {
        $grant = new ClientGrant(
            $this->app->make(UserRepository::class),
            $this->app->make(RefreshTokenRepository::class)
        );

        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

        return $grant;
    }

    protected function setAuthProvider()
    {
        $grantType = $this->app->request->get('grant_type', 'personal');
        $provider = config('auth.grant_type_to_provider.' . $grantType);
        config(['auth.guards.api.provider' => $provider]);
    }

    /**
     * Register the token guard.
     *
     * @return void
     */
    protected function registerGuard()
    {
        Auth::extend('passport', function ($app, $name, array $config) {
            return tap($this->makeGuard($config), function ($guard) {
                $this->app->refresh('request', $guard, 'setRequest');
            });
        });
    }

    /**
     * Make an instance of the token guard.
     *
     * @param  array $config
     * @return \Illuminate\Auth\RequestGuard
     */
    protected function makeGuard(array $config)
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new TokenGuard(
                $this->app->make(ResourceServer::class),
                Auth::createUserProvider($config['provider']),
                $this->app->make(TokenRepository::class),
                $this->app->make(ClientRepository::class),
                $this->app->make('encrypter')
            ))->user($request);
        }, $this->app['request']);
    }
}
