/*
 * File: middleware.ts
 * Created Date: Aug 24, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

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
