<?php

declare(strict_types=1);

/*
 * This file is part of the Vigie Bundle.
 *
 * (c) Loïc Sapone <loic@sapone.fr>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace IQ2i\VigieBundle\Model;

enum ActivityType: string
{
    case HttpRequest = 'http_request';
    case LoginSuccess = 'login_success';
    case LoginFailure = 'login_failure';
    case Logout = 'logout';
    case SwitchUser = 'switch_user';
    case TokenDeauthenticated = 'token_deauthenticated';
    case AccessDenied = 'access_denied';
    case PasswordChanged = 'password_changed';
    case RolesChanged = 'roles_changed';
    case CsrfFailure = 'csrf_failure';
    case Custom = 'custom';
}
