declare module '@ioc:Adonis/Addons/Zeytech/AuthenticateMiddleware' {
  import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
  /**
   * Shape of the authenticate middleware class constructor
   */
  export interface AuthenticateMiddlewareContract {
    new (): {
      handle(ctx: HttpContextContract, next: () => void): any
    }
  }

  const AuthenticateMiddleware: AuthenticateMiddlewareContract
  export default AuthenticateMiddleware
}
