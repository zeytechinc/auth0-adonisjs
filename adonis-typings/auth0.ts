declare module '@ioc:Adonis/Addons/Zeytech/Auth0' {
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
    getUser(id: string): Promise<User>
    getRoles(): Promise<Role[]>
    verifyToken(bearerToken: string): Promise<JwtPayload>
    grantRole(auth0RoleId: string, auth0UserId: string)
    revokeRole(auth0RoleId: string, auth0UserId: string)
    changeEmail(auth0UserId: string, newEmail: string, requestVerification: Boolean)
    updateUserProfile(auth0UserId: string, userProfile: Partial<UpdateUserData>)
  }

  const Auth0Service: Auth0ServiceContract
  export default Auth0Service
}
