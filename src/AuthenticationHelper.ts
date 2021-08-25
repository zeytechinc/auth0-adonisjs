import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { ConfigContract } from '@ioc:Adonis/Core/Config'
import { RequestContract } from '@ioc:Adonis/Core/Request'
import { AuthenticationHelperContract } from '@ioc:Adonis/Addons/Zeytech/Auth0Service'
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
