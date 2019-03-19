# Auth Client

## Requirements

  - laravel/framework: 5.7.*
  - laravel/passport: ^7.0

## Installation

The library can be installed using Composer.

Add vcs repository url to the `composer.json`:

```json
"repositories": [
    {
        "type": "vcs",
        "url": "git@github.com:namewithin/auth-client.git"
    }
]
```

Install

```bash
composer require namewithin/auth-client
```


## Usage

You can define guard with the client provider in the `configs/auth.php`
```php
'guards' => [
    'client-guard' => [
        'driver-guard'   => 'client-driver',
        'provider' => 'client',
    ],
],
```

Now you can protect your routes, only need to add the auth guard to auth middleware:
```php
Route::get('profile', function () {
    // Only authenticated clients may enter...
})->middleware('auth:client-guard');

Route::group([
    'middleware' => ['auth:api,client-guard'], // Only authenticated users and clients may enter...
], function () {
    Route::get('ticket/{id}/history', 'HistoryController@ticket');
});
```
