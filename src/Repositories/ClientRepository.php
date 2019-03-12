<?php

namespace PDFfiller\SupervisorAuth\Repositories;

use Laravel\Passport\ClientRepository as PassportClientRepository;
use Illuminate\Database\Eloquent\Model;

class ClientRepository extends PassportClientRepository
{
    /**
     * @param Illuminate\Database\Eloquent\Model $client
     * @param Illuminate\Database\Eloquent\Model $user
     *
     * @return bool
     */
    public function validateProvider(Model $client, Model $user): bool
    {
        if ($client->personal_access_client == 1) {
            $grantType = 'personal';
        } elseif ($client->password_client == 1 && $client->with_dummy_user == 0) {
            $grantType = 'password';
        } elseif ($client->password_client == 1 && $client->with_dummy_user == 1) {
            $grantType = 'dummy_user';
        }

        if (!isset($grantType)) {
            return false;
        }

        $provider = config('auth.grant_type_to_provider.' . $grantType);
        $providerModel = config('auth.providers.' . $provider . '.model');
        $userModel = get_class($user);

        return $providerModel === $userModel;
    }
}
