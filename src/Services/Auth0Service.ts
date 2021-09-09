/*
 * File: Auth0Service.ts
 * Created Date: Aug 26, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { AppMetadata, ManagementClient, Role, UpdateUserData, User, UserMetadata } from 'auth0'
import { ConfigContract } from '@ioc:Adonis/Core/Config'
import { LoggerContract } from '@ioc:Adonis/Core/Logger'
import { promisify } from 'util'
import * as jwt from 'jsonwebtoken'
import { Auth0ClientConfig, Auth0ServiceContract } from '@ioc:Adonis/Addons/Zeytech/Auth0Service'
import { Exception } from '@adonisjs/core/build/standalone'
import { TLRUCacheContract } from '@ioc:Adonis/Addons/Zeytech/Cache/TLRUCache'
import { CacheManagerContract } from '@ioc:Adonis/Addons/Zeytech/Cache'
import jwksClientConstructor from 'jwks-rsa'

const jwtVerify = promisify<
  string,
  jwt.Secret | jwt.GetPublicKeyOrSecret,
  jwt.VerifyOptions,
  jwt.VerifyCallback
>(jwt.verify)

const userCacheKey = 'users'
const roleCacheKey = 'roles'

export default class Auth0Service implements Auth0ServiceContract {
  private mgmtClient: ManagementClient
  private cert: string | jwt.GetPublicKeyOrSecret

  constructor(
    private config: ConfigContract,
    private logger: LoggerContract,
    private cacheManager: CacheManagerContract
  ) {
    const clientConfig = config.get('zeytech-auth0.auth0Config')
    this.mgmtClient = new ManagementClient(clientConfig)
    const cacheConfig = config.get('zeytech-auth0.cache')
    this.cacheManager.createTLRUCache(
      userCacheKey,
      cacheConfig.users.maxSize,
      cacheConfig.users.maxAge * 1000, // config is in sec.  cache accepts ms
      cacheConfig.users.engine,
      'User Cache',
      cacheConfig.users.connectionName
    )
    this.cacheManager.createTLRUCache(
      roleCacheKey,
      cacheConfig.roles.maxSize,
      cacheConfig.roles.maxAge * 1000, // config is in sec.  cache accepts ms
      cacheConfig.roles.engine,
      'Role Cache',
      cacheConfig.roles.connectionName
    )
  }

  private async lazyLoadDeps() {
    if (!this.cert) {
      const config = this.config.get('zeytech-auth0', {})
      this.cert = config.jwtCert || ''

      if (!this.cert) {
        const jwksDomain = config.auth0Config.domain || ''
        if (!jwksDomain) {
          this.logger.error('No jwks uri')
          throw new Exception('Cannot verify user.  Invalid config', 401, 'E_A0_VERIFY_CONFIG')
        }
        const jwksClient = jwksClientConstructor({
          jwksUri: `https://${jwksDomain}/.well-known/jwks.json`,
        })
        this.cert = (header, callback) => {
          jwksClient.getSigningKey(header.kid, function (err, key) {
            if (err) {
              callback(err)
            }
            const signingKey = key.getPublicKey()
            callback(null, signingKey)
          })
        }
      }
    }
  }

  public async verifyToken(bearerToken: string): Promise<jwt.JwtPayload> {
    try {
      await this.lazyLoadDeps()
      // See items 1 & 2 of https://auth0.com/docs/tokens/access-tokens/validate-access-tokens
      const decodedToken: jwt.JwtPayload = await jwtVerify(bearerToken, this.cert, {})
      const authConfig = this.config.get('zeytech-auth0.auth0Config') as Auth0ClientConfig
      if (!decodedToken.aud?.includes(authConfig.audience)) {
        throw new Exception('unauthorized', 401, 'E_A0_INVALID_AUD')
      }
      return decodedToken
    } catch (err) {
      this.logger.error('Error verifying token: %o', JSON.stringify(err))
      if (err.code) {
        throw err
      } else {
        throw new Exception('unauthorized', 401, 'E_A0_VERIFY')
      }
    }
  }

  // Users
  public async getAllUsers(): Promise<User[]> {
    return await this.mgmtClient.getUsers()
  }

  public async getUser(id: string): Promise<User<UserMetadata, AppMetadata>> {
    const cache = this.cacheManager.getTLRUCache<User<UserMetadata, AppMetadata>>(userCacheKey)
    const user = await cache?.get(id)
    if (user) {
      return user as User<UserMetadata, AppMetadata>
    }
    const freshUser = await this.mgmtClient.getUser({ id })
    cache?.set(id, freshUser)
    return freshUser
  }

  public async updateUser(auth0UserId: string, userData: Partial<UpdateUserData>): Promise<User> {
    return await this.mgmtClient.updateUser({ id: auth0UserId }, userData)
  }

  public async getAllUserRoles(auth0UserId: string): Promise<Role[]> {
    return await this.mgmtClient.getUserRoles({ id: auth0UserId })
  }

  public async addUserRole(auth0RoleId: string, auth0UserId: string): Promise<Boolean> {
    await this.mgmtClient.assignRolestoUser({ id: auth0UserId }, { roles: [auth0RoleId] })
    return true
  }

  public async removeUserRole(auth0RoleId: string, auth0UserId: string): Promise<Boolean> {
    await this.mgmtClient.removeRolesFromUser({ id: auth0UserId }, { roles: [auth0RoleId] })
    return true
  }

  public async updateUserEmail(auth0UserId: string, newEmail: string): Promise<User> {
    return await this.updateUser(auth0UserId, { email: newEmail })
  }

  // Roles
  public async getAllRoles(): Promise<Role[]> {
    return await this.mgmtClient.getRoles()
  }

  public async getRole(auth0RoleId: string): Promise<Role> {
    const cache = this.cacheManager.getTLRUCache<User<UserMetadata, AppMetadata>>(roleCacheKey)
    const role = await cache?.get(auth0RoleId)
    if (role) {
      return role
    }
    const freshRole = await this.mgmtClient.getRole({ id: auth0RoleId })
    cache?.set(auth0RoleId, freshRole)
    return freshRole
  }

  public async getRoleUsers(auth0RoleId: string): Promise<User[]> {
    return await this.mgmtClient.getUsersInRole({ id: auth0RoleId })
  }

  public get userCache(): TLRUCacheContract<User<UserMetadata, AppMetadata>> {
    return this.cacheManager.getTLRUCache<User<UserMetadata, AppMetadata>>(userCacheKey)!
  }

  public get roleCache(): TLRUCacheContract<Role[]> {
    return this.cacheManager.getTLRUCache<Role[]>(roleCacheKey)!
  }

  public async clearUserCache() {
    return this.userCache.clear()
  }

  public async clearRoleCache() {
    return this.roleCache.clear()
  }
}
