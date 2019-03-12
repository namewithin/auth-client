<?php

namespace PDFfiller\SupervisorAuth\Models;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\HasApiTokens;
use Venturecraft\Revisionable\RevisionableTrait;

class ClientUser extends Authenticatable
{
    use HasApiTokens, SoftDeletes, RevisionableTrait, Notifiable;

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'client_users';

    protected $guard_name = 'api';

    protected $fillable = [
        'email',
        'password',
        'encrypted_password',
    ];

    protected $dates = [
        'created_at',
        'updated_at',
        'deleted_at'
    ];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'encrypted_password',
        'remember_token',
    ];
}
