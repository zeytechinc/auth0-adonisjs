/*
 * @zeytech/adonis-auth0
 *
 * (c) Zeytech Inc.
 */
import { ApplicationContract } from '@ioc:Adonis/Core/Application'
import { AuthenticationHelper } from '../src/AuthenticationHelper'
import { AuthenticateMiddleware } from '../src/Middleware/Authenticate'
import Auth0Service from '../src/Services/Auth0Service'

export default class Auth0Provider {
  constructor(protected app: ApplicationContract) {}

  public static needsApplication = true

  public register() {
    this.app.container.singleton('Adonis/Addons/Zeytech/Auth0/Auth0Service', () => {
      const config = this.app.container.resolveBinding('Adonis/Core/Config')
      const logger = this.app.container.resolveBinding('Adonis/Core/Logger')
      return new Auth0Service(config, logger)
    })

    this.app.container.singleton('Adonis/Addons/Zeytech/Auth0/AuthenticateMiddleware', () => {
      const config = this.app.container.resolveBinding('Adonis/Core/Config')
      const authService = this.app.container.resolveBinding(
        'Adonis/Addons/Zeytech/Auth0/Auth0Service'
      )
      const authHelper = new AuthenticationHelper(config, authService)
      return new AuthenticateMiddleware(authHelper)
    })
  }

  public async boot() {}
}
