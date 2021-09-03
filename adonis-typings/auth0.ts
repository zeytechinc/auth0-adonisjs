declare module '@ioc:Adonis/Addons/Zeytech/Auth0Service' {
  import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
  import { RequestContract } from '@ioc:Adonis/Core/Request'
  import { Role, User, UpdateUserData } from 'auth0'
  import { JwtPayload } from 'jsonwebtoken'

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
    cache: Auth0CacheConfig

    /* engine: 'memory', // Valid values: 'memory' | 'redis'
    users: {
      maxSize: 50,
      maxAage: 900, // in seconds
      connectionName: 'cache', // Used only if engine is 'redis'
    },
    roles: {
      maxSize: 0,
      maxAge: 3600, // in seconds
      connectionName: 'cache', // Used only if engine is 'redis'
    }, */
  }

  export interface Auth0ServiceContract {
    verifyToken(bearerToken: string): Promise<JwtPayload>
    getAllUsers(): Promise<User[]>
    getUser(id: string): Promise<User>
    updateUser(auth0UserId: string, userData: Partial<UpdateUserData>): Promise<User>
    getAllUserRoles(auth0UserId: string): Promise<Role[]>
    addUserRole(auth0RoleId: string, auth0UserId: string): Promise<Boolean>
    removeUserRole(auth0RoleId: string, auth0UserId: string): Promise<Boolean>
    updateUserEmail(auth0UserId: string, newEmail: string): Promise<User>
    getAllRoles(): Promise<Role[]>
    getRole(auth0RoleId: string): Promise<Role>
    getRoleUsers(auth0RoleId: string): Promise<User[]>
    clearUserCache(): Promise<void>
    clearRoleCache(): Promise<void>
  }

  const Auth0Service: Auth0ServiceContract
  export default Auth0Service
}
