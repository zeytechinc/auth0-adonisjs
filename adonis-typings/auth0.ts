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
  }

  const Auth0Service: Auth0ServiceContract
  export default Auth0Service
}
