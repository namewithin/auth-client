<?php

namespace Supervisor\Auth\Guards;

use Exception;
use Firebase\JWT\JWT;
use Laravel\Passport\Passport;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;

class ClientGuard implements Guard
{
    use GuardHelpers;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;
    /**
     * The resource server instance.
     *
     * @var \League\OAuth2\Server\ResourceServer
     */
    protected $server;
    /**
     * The user provider implementation.
     *
     * @var \Illuminate\Contracts\Auth\UserProvider
     */
    protected $provider;
    /**
     * The token repository instance.
     *
     * @var \Laravel\Passport\TokenRepository
     */
    protected $tokens;
    /**
     * The client repository instance.
     *
     * @var \Laravel\Passport\ClientRepository
     */
    protected $clients;
    /**
     * The encrypter implementation.
     *
     * @var \Illuminate\Contracts\Encryption\Encrypter
     */
    protected $encrypter;
    /**
     * The client repository instance.
     *
     * @var \Laravel\Passport\ClientRepository
     */
    private $client;

    /**
     * Create a new token guard instance.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \League\OAuth2\Server\ResourceServer  $server
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \Laravel\Passport\TokenRepository  $tokens
     * @param  \Laravel\Passport\ClientRepository  $client
     * @param  \Illuminate\Contracts\Encryption\Encrypter  $encrypter
     * @return void
     */
    public function __construct(
        Request $request,
        ResourceServer $server,
        UserProvider $provider,
        TokenRepository $tokens,
        ClientRepository $client,
        Encrypter $encrypter
    ) {
        $this->request = $request;
        $this->server = $server;
        $this->tokens = $tokens;
        $this->client = $client;
        $this->provider = $provider;
        $this->encrypter = $encrypter;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user(): ?Authenticatable
    {
        if (is_null($this->user)) {
            $oauthClient = $this->oauthClient($this->request);

            if (is_null($oauthClient)) {
                return null;
            }

            $identifier = $oauthClient->user_id;
            $this->user = $this->provider->retrieveById($identifier);
        }

        return $this->user;
    }

    /**
     * Get the client for the incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    public function oauthClient(Request $request): ?Client
    {
        if ($request->bearerToken()) {
            if (! $psr = $this->getPsrRequestViaBearerToken($request)) {
                return null;
            }

            $client = $this->client->findActive(
                $psr->getAttribute('oauth_client_id')
            );
        } elseif ($request->cookie(Passport::cookie())) {
            if ($token = $this->getTokenViaCookie($request)) {
                $client = $this->client->findActive($token['aud']);
            }
        }

        if (empty($client)) {
            return null;
        }

        return $this->validateClient($client) ? $client : null;
    }

    /**
     * Authenticate and get the incoming PSR-7 request via the Bearer token.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Psr\Http\Message\ServerRequestInterface
     */
    protected function getPsrRequestViaBearerToken($request)
    {
        // First, we will convert the Symfony request to a PSR-7 implementation which will
        // be compatible with the base OAuth2 library. The Symfony bridge can perform a
        // conversion for us to a Zend Diactoros implementation of the PSR-7 request.
        $psr = (new DiactorosFactory)->createRequest($request);

        try {
            return $this->server->validateAuthenticatedRequest($psr);
        } catch (OAuthServerException $e) {
            $request->headers->set('Authorization', '', true);

            Container::getInstance()->make(
                ExceptionHandler::class
            )->report($e);
        }
    }

    /**
     * Get the token cookie via the incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function getTokenViaCookie($request)
    {
        // If we need to retrieve the token from the cookie, it'll be encrypted so we must
        // first decrypt the cookie and then attempt to find the token value within the
        // database. If we can't decrypt the value we'll bail out with a null return.
        try {
            $token = $this->decodeJwtTokenCookie($request);
        } catch (Exception $e) {
            return;
        }

        // We will compare the CSRF token in the decoded API token against the CSRF header
        // sent with the request. If the two don't match then this request is sent from
        // a valid source and we won't authenticate the request for further handling.
        if (! Passport::$ignoreCsrfToken && (! $this->validCsrf($token, $request) ||
                time() >= $token['expiry'])) {
            return;
        }

        return $token;
    }

    /**
     * Decode and decrypt the JWT token cookie.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    protected function decodeJwtTokenCookie($request)
    {
        return (array) JWT::decode(
            $this->encrypter->decrypt($request->cookie(Passport::cookie()), Passport::$unserializesCookies),
            $this->encrypter->getKey(),
            ['HS256']
        );
    }

    /**
     * Determine if the CSRF / header are valid and match.
     *
     * @param  array  $token
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function validCsrf($token, $request)
    {
        return isset($token['csrf']) && hash_equals(
                $token['csrf'], (string) $request->header('X-CSRF-TOKEN')
            );
    }

    public function validateClient($client): bool
    {
        return $client->personal_access_client == 0 && $client->password_client == 0;
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
