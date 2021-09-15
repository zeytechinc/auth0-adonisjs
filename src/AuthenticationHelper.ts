/*
 * File: AuthenticationHelper.ts
 * Created Date: Aug 26, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { ConfigContract } from '@ioc:Adonis/Core/Config'
import { RequestContract } from '@ioc:Adonis/Core/Request'
import {
  Auth0AdonisConfig,
  AuthenticationHelperContract,
} from '@ioc:Adonis/Addons/Zeytech/Auth0Service'
import Auth0Service from './Services/Auth0Service'
import { Exception } from '@adonisjs/core/build/standalone'

export class AuthenticationHelper implements AuthenticationHelperContract {
  private cert: string

  constructor(private config: ConfigContract, private authService: Auth0Service) {}

  private lazyLoadDeps() {
    if (!this.cert) {
      this.cert = this.config.get('zeytech-auth0.jwtCert')
    }
  }

  public async verifyAuthToken(
    ctx: HttpContextContract,
    extractTokenData?: (token: any, request: RequestContract) => any
  ) {
    this.lazyLoadDeps()

    let bearerToken = ctx.request.header('authorization')
    if (bearerToken) {
      bearerToken = bearerToken.replace('Bearer ', '')
      ctx.request.token = bearerToken

      try {
        const decodedToken = await this.authService.verifyToken(bearerToken)
        ctx.request.auth = decodedToken
        ctx.request.userId = decodedToken.sub
        ctx.request.audience = decodedToken.aud

        if (this.config.get('auth') && decodedToken.sub) {
          const authConfig = this.config.get('auth')
          const zeytechAuthConfig = this.config.get('zeytech-auth0') as Auth0AdonisConfig
          const auth0User = await this.authService.getUser(decodedToken.sub)
          ctx.request.email = auth0User.email
          let userId = decodedToken.sub

          if (zeytechAuthConfig.localUsers) {
            const UserModel = (await authConfig.guards[authConfig.guard].provider.model()).default

            if (UserModel) {
              const lookupKey = zeytechAuthConfig.localUsers.lookupKey || 'email'
              if (zeytechAuthConfig.localUsers.createWhenMissing) {
                const searchOpts = {}
                switch (lookupKey) {
                  case 'email':
                    searchOpts['email'] = auth0User.email
                    break
                  case 'id':
                    searchOpts['id'] = decodedToken.sub
                }

                const user = await UserModel.firstOrCreate(searchOpts, {})
                if (user) {
                  userId = user.id
                }
              }
            } else {
              console.log('no user model in app or id on token')
            }
          }
          if (ctx.auth) {
            // @ts-ignore - this is fine at runtime.  TS hates it because GuardsList has no structure
            await ctx.auth.use(authConfig.guard).login(Object.assign({ id: userId }, auth0User))
          }
        }

        const rolesKey = this.config.get('zeytech-auth0.tokenRolesKey')
        if (rolesKey) {
          ctx.request.roles = decodedToken[rolesKey]
        }

        // This hook function allows apps to further expand the request contract and
        // read more data out of the token and add it to the request object if they wish.
        if (extractTokenData) {
          extractTokenData(decodedToken, ctx.request)
        }
      } catch (err) {
        ctx.logger.error(`Error verifying token: ${JSON.stringify(err, null, 2)}`)
        throw err
      }
    } else {
      throw new Exception('unauthorized', 401, 'E_A0_TOKEN_REQUIRED')
    }
  }
}
