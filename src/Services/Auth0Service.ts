import { ManagementClient, Role, UpdateUserData, User } from 'auth0'
import { ConfigContract } from '@ioc:Adonis/Core/Config'
import { LoggerContract } from '@ioc:Adonis/Core/Logger'
import { promisify } from 'util'
import * as jwt from 'jsonwebtoken'
import { Auth0ClientConfig } from '@ioc:Adonis/Addons/Zeytech/Auth0Service'
import { Exception } from '@adonisjs/core/build/standalone'

const jwtVerify = promisify<
  string,
  jwt.Secret | jwt.GetPublicKeyOrSecret,
  jwt.VerifyOptions,
  jwt.VerifyCallback
>(jwt.verify)

export default class Auth0Service {
  private mgmtClient: ManagementClient
  private cert: string

  constructor(private config: ConfigContract, private logger: LoggerContract) {
    const clientConfig = config.get('zeytech-auth0.auth0Config')
    this.mgmtClient = new ManagementClient(clientConfig)
  }

  private lazyLoadDeps() {
    if (!this.cert) {
      this.cert = this.config.get('zeytech-auth0.jwtCert')
    }
  }

  public async getUser(id: string): Promise<User> {
    // TODO: Add caching to avoid being rate limited
    return await this.mgmtClient.getUser({ id })
  }

  public async getRoles(): Promise<Role[]> {
    // TODO: Add caching to avoid being rate limited
    return await this.mgmtClient.getRoles()
  }

  public async verifyToken(bearerToken: string): Promise<jwt.JwtPayload> {
    try {
      this.lazyLoadDeps()
      // See items 1 & 2 of https://auth0.com/docs/tokens/access-tokens/validate-access-tokens
      const decodedToken: jwt.JwtPayload = await jwtVerify(bearerToken, this.cert, {})
      const authConfig = this.config.get('zeytech-auth0.auth0Config') as Auth0ClientConfig
      if (!decodedToken.aud?.includes(authConfig.audience)) {
        throw new Exception('unauthorized', 401, 'E_A0_INVALID_AUD')
      }
      return decodedToken
    } catch (err) {
      this.logger.error('Error verifying token: %o', JSON.stringify(err))
      throw new Exception('unauthorized', 401, 'E_A0_VERIFY')
    }
  }

  // TODO: When implementing these functions, update the return typescript signature appropriately.

  public async grantRole(auth0RoleId: string, auth0UserId: string) {
    await this.mgmtClient.assignRolestoUser({ id: auth0UserId }, { roles: [auth0RoleId] })
    return true
  }

  public async revokeRole(auth0RoleId: string, auth0UserId: string) {
    await this.mgmtClient.removeRolesFromUser({ id: auth0UserId }, { roles: [auth0RoleId] })
    return true
  }

  public async changeEmail(auth0UserId: string, newEmail: string) {
    await this.updateUserProfile(auth0UserId, { email: newEmail })
    return true
  }

  public async updateUserProfile(auth0UserId: string, userProfile: Partial<UpdateUserData>) {
    await this.mgmtClient.updateUser({ id: auth0UserId }, userProfile)
    return true
  }
}
