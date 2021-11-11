/*
 * File: auth0.ts
 * Created Date: Aug 26, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare module '@ioc:Adonis/Addons/Zeytech/Auth0Service' {
  import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
  import { RequestContract } from '@ioc:Adonis/Core/Request'
  import { Role, User, UpdateUserData, CreateUserData, ManagementClient } from 'auth0'
  import { JwtPayload } from 'jsonwebtoken'
  import { LucidRow } from '@ioc:Adonis/Lucid/Orm'

  export interface AuthenticationHelperContract {
    verifyAuthToken(
      ctx: HttpContextContract,
      extractTokenData?: (token: any, request: RequestContract) => any
    )
  }

  export interface Auth0TokenClaims {
    iss?: string
    sub?: string
    aud?: string | string[]
    iat?: number
    exp?: number
    azp?: string
    [key: string]: any
  }

  export interface Auth0ClientConfig {
    clientId: string
    clientSecret: string
    domain: string
    audience: string
    scope: string
  }

  export interface Auth0CacheHealthCheckConfig {
    enabled: boolean
    includeItems?: boolean
    dateFormat?: string
  }

  export interface Auth0CacheInstanceConfig {
    maxSize: number
    maxAge?: number
    connectionName?: string
    engine: 'memory' | 'redis'
    healthCheck: boolean | Auth0CacheHealthCheckConfig
  }

  export interface Auth0CacheConfig {
    users: Auth0CacheInstanceConfig
    roles: Auth0CacheInstanceConfig
  }

  export interface CacheLastAccessInfo {
    utc: string
    localTz: string
    age: number
    ageDesc: string
  }

  export interface Auth0AdonisConfig {
    auth0Config: Auth0ClientConfig
    jwtCert?: string
    tokenRolesKey?: string
    localRoles?: boolean
    localUsers?:
      | {
          createWhenMissing: boolean
          lookupKey: string
        }
      | false
    userLookupKey?: string
    cache: Auth0CacheConfig
  }

  export interface Auth0ServiceContract {
    verifyToken(bearerToken: string): Promise<JwtPayload>
    getAllUsers(): Promise<User[]>
    getUser(id: string): Promise<User>
    createUser(userData: CreateUserData): Promise<User>
    updateUser(auth0UserId: string, userData: Partial<UpdateUserData>): Promise<User>
    getAllUserRoles(auth0UserId: string): Promise<Role[] | LucidRow[]>
    addUserRole(roleId: string, auth0UserId: string): Promise<Boolean>
    removeUserRole(roleId: string, auth0UserId: string): Promise<Boolean>
    updateUserEmail(auth0UserId: string, newEmail: string): Promise<User>
    getAllRoles(): Promise<Role[] | LucidRow[]>
    getRole(roleId: string | number): Promise<Role | LucidRow | null>
    getRoleUsers(roleId: string | number): Promise<User[] | LucidRow[]>
    clearUserCache(): Promise<void>
    clearRoleCache(): Promise<void>
    rawManagementClient: ManagementClient
  }

  const Auth0Service: Auth0ServiceContract
  export default Auth0Service
}
