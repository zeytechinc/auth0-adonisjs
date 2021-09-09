/*
 * File: Authenticate.ts
 * Created Date: Aug 20, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/// <reference path="../../adonis-typings/middleware.ts" />

import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { AuthenticationHelperContract } from '@ioc:Adonis/Addons/Zeytech/Auth0Service'

export class AuthenticateMiddleware {
  constructor(private authHelper: AuthenticationHelperContract) {}

  public async handle(ctx: HttpContextContract, next: () => Promise<void>) {
    await this.authHelper.verifyAuthToken(ctx) // if fails, throws exception
    await next()
  }
}
