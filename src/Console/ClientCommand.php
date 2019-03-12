<?php

namespace Supervisor\Auth\Console;

use Illuminate\Support\Facades\Hash;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Console\ClientCommand as PassportClientCommand;
use Laravel\Passport\Passport;
use Supervisor\Auth\Models\Client;

class ClientCommand extends PassportClientCommand
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'passport:client
            {--personal : Create a personal access token client}
            {--password : Create a password grant client}
            {--client : Create a client credentials grant client}
            {--client-related : Create a client related grant}
            {--name= : The name of the client}
            {--redirect_uri= : The URI to redirect to after authorization }
            {--user_id= : The user ID the client should be assigned to }';

    /**
     * Execute the console command.
     *
     * @param  \Laravel\Passport\ClientRepository $clients
     * @return void
     */
    public function handle(ClientRepository $clients)
    {
        if ($this->option('client-related')) {
            return $this->createClientWithDummyUser($clients);
        }

        parent::handle($clients);
    }

    /**
     * Create a new access client with dummy user.
     *
     * @param  \Laravel\Passport\ClientRepository $clients
     * @return void
     */
    protected function createClientWithDummyUser(ClientRepository $clients)
    {
        $name = $this->option('name') ?: $this->ask(
            'What should we name grant associated with the client?',
            config('app.name') . ' Client Related Grant Client'
        );

        Passport::useClientModel(Client::class);

        $client = $clients->createPasswordGrantClient(
            null, $name, ''
        );

        $this->associateWithDummyUser($client);

        $this->info('Password grant client created successfully.');
        $this->line('<comment>Client ID:</comment> ' . $client->id);
        $this->line('<comment>Client Secret:</comment> ' . $client->secret);
    }

    /**
     * @param Client $client
     */
    protected function associateWithDummyUser(Client $client)
    {
        $password = str_random(10);

        $clientUser = $client->user()->create([
            'email'              => 'dummy.' . $client->id . '@user.com',
            'password'           => Hash::make($password),
            'encrypted_password' => encrypt($password),
        ]);

        $client->user_id = $clientUser->id;
        $client->with_dummy_user = true;
        $client->save();
    }
}
