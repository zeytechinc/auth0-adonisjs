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

  // Users
  public async getAllUsers(): Promise<User[]> {
    return await this.mgmtClient.getUsers()
  }

  public async getUser(id: string): Promise<User> {
    return await this.mgmtClient.getUser({ id })
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
    return await this.mgmtClient.getRole({ id: auth0RoleId })
  }

  public async getRoleUsers(auth0RoleId: string): Promise<User[]> {
    return await this.mgmtClient.getUsersInRole({ id: auth0RoleId })
  }
}
