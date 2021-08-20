declare module '@ioc:Adonis/Addons/Zeytech/Auth0' {
  import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
  import { RequestContract } from '@ioc:Adonis/Core/Request'
  import { Role, User } from 'auth0'
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

  export interface Auth0Service {
    getUser(id: string): Promise<User>
    getRoles(): Promise<Role[]>
    verifyToken(bearerToken: string): Promise<JwtPayload>
  }
}
