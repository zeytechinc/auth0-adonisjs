/*
 * File: Auth0Provider.ts
 * Created Date: Aug 26, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
import { ApplicationContract } from '@ioc:Adonis/Core/Application'
import { CacheManagerContract } from '@ioc:Adonis/Addons/Zeytech/Cache'
import { AuthenticationHelper } from '../src/AuthenticationHelper'
import { AuthenticateMiddleware } from '../src/Middleware/Authenticate'
import Auth0Service from '../src/Services/Auth0Service'

export default class Auth0Provider {
  constructor(protected app: ApplicationContract) {}

  public static needsApplication = true

  public register() {}

  public async boot() {
    const config = this.app.container.resolveBinding('Adonis/Core/Config')
    this.app.container.singleton('Adonis/Addons/Zeytech/Auth0Service', () => {
      const cacheManager: CacheManagerContract = this.app.container.resolveBinding(
        'Skrenek/Adonis/Cache/CacheManager'
      )
      const logger = this.app.container.resolveBinding('Adonis/Core/Logger')
      return new Auth0Service(config, logger, cacheManager)
    })

    this.app.container.singleton('Adonis/Addons/Zeytech/AuthenticateMiddleware', () => {
      const authService = this.app.container.resolveBinding('Adonis/Addons/Zeytech/Auth0Service')
      const authHelper = new AuthenticationHelper(config, authService)
      return new AuthenticateMiddleware(authHelper)
    })

    const HealthCheck = this.app.container.use('Adonis/Core/HealthCheck')
    const authService = this.app.container.resolveBinding(
      'Adonis/Addons/Zeytech/Auth0Service'
    ) as Auth0Service

    const cacheConfig = config.get('zeytech-auth0.cache')
    if (cacheConfig.users.healthCheck) {
      const userChecker = await authService.userCache.getHealthChecker(
        cacheConfig.users.healthCheck.includeItems,
        cacheConfig.users.healthCheck.dateFormat
      )
      HealthCheck.addChecker('userCache', userChecker)
    }
    if (cacheConfig.roles.healthCheck) {
      const roleChecker = await authService.roleCache.getHealthChecker(
        cacheConfig.roles.healthCheck.includeItems,
        cacheConfig.roles.healthCheck.dateFormat
      )
      HealthCheck.addChecker('roleCache', roleChecker)
    }
  }
}
