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
