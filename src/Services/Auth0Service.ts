/*
 * File: Auth0Service.ts
 * Created Date: Aug 26, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import {
  AppMetadata,
  CreateUserData,
  ManagementClient,
  Role,
  UpdateUserData,
  User,
  UserMetadata,
} from 'auth0'
import { ConfigContract } from '@ioc:Adonis/Core/Config'
import { LoggerContract } from '@ioc:Adonis/Core/Logger'
import { promisify } from 'util'
import * as jwt from 'jsonwebtoken'
import { Auth0ClientConfig, Auth0ServiceContract } from '@ioc:Adonis/Addons/Zeytech/Auth0Service'
import { Exception } from '@adonisjs/core/build/standalone'
import { TLRUCacheContract } from '@ioc:Adonis/Addons/Zeytech/Cache/TLRUCache'
import { CacheManagerContract } from '@ioc:Adonis/Addons/Zeytech/Cache'
import jwksClientConstructor from 'jwks-rsa'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'
import { BaseModel, LucidRow } from '@ioc:Adonis/Lucid/Orm'

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

  private _applicationRole: typeof BaseModel
  private get applicationRole() {
    this._applicationRole =
      this._applicationRole || this.app.container.use('App/Models/ApplicationRole').default
    return this._applicationRole
  }

  private _userApplicationRole: typeof BaseModel
  private get userApplicationRole() {
    this._userApplicationRole =
      this._userApplicationRole || this.app.container.use('App/Models/UserApplicationRole').default
    return this._userApplicationRole
  }

  private auth0Roles = false

  constructor(
    private config: ConfigContract,
    private logger: LoggerContract,
    private cacheManager: CacheManagerContract,
    private app: ApplicationContract
  ) {
    this.auth0Roles = !config.get('zeytech-auth0.localRoles')
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

  public async createUser(data: CreateUserData): Promise<User> {
    return await this.mgmtClient.createUser(data)
  }

  public async updateUser(auth0UserId: string, userData: Partial<UpdateUserData>): Promise<User> {
    return await this.mgmtClient.updateUser({ id: auth0UserId }, userData)
  }

  public async getAllUserRoles(auth0UserId: string): Promise<Role[] | LucidRow[]> {
    if (this.auth0Roles) {
      return await this.mgmtClient.getUserRoles({ id: auth0UserId })
    } else {
      return await this.applicationRole
        .query()
        .whereHas('userApplicationRoles' as any, (userApplicationRolesQuery) => {
          userApplicationRolesQuery.where('user_id', '=', auth0UserId)
        })
    }
  }

  public async addUserRole(roleId: string | number, auth0UserId: string): Promise<Boolean> {
    if (this.auth0Roles) {
      await this.mgmtClient.assignRolestoUser({ id: auth0UserId }, { roles: [roleId as string] })
      return true
    } else {
      await this.userApplicationRole.create({
        userId: auth0UserId,
        applicationRoleId: roleId as number,
      })
      return true
    }
  }

  public async removeUserRole(roleId: string | number, auth0UserId: string): Promise<Boolean> {
    if (this.auth0Roles) {
      await this.mgmtClient.removeRolesFromUser({ id: auth0UserId }, { roles: [roleId as string] })
      return true
    } else {
      await this.userApplicationRole
        .query()
        .where('user_id', '=', auth0UserId)
        .where('application_role_id', '=', roleId)
        .delete()
      return true
    }
  }

  public async updateUserEmail(auth0UserId: string, newEmail: string): Promise<User> {
    return await this.updateUser(auth0UserId, { email: newEmail })
  }

  // Roles
  public async getAllRoles(): Promise<Role[] | LucidRow[]> {
    if (this.auth0Roles) {
      return await this.mgmtClient.getRoles()
    } else {
      return await this.applicationRole.all()
    }
  }

  public async getRole(roleId: string | number): Promise<Role | LucidRow | null> {
    if (this.auth0Roles) {
      const cache = this.cacheManager.getTLRUCache<User<UserMetadata, AppMetadata>>(roleCacheKey)
      const role = await cache?.get(roleId as string)
      if (role) {
        return role
      }
      const freshRole = await this.mgmtClient.getRole({ id: roleId as string })
      cache?.set(roleId as string, freshRole)
      return freshRole
    } else {
      return await this.applicationRole.find(roleId as number)
    }
  }

  public async getRoleUsers(roleId: string | number): Promise<User[] | LucidRow[]> {
    if (this.auth0Roles) {
      return await this.mgmtClient.getUsersInRole({ id: roleId as string })
    } else {
      return await this.userApplicationRole
        .query()
        .where('application_role_id', '=', roleId as number)
    }
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

  public get rawManagementClient(): ManagementClient {
    return this.mgmtClient
  }
}
