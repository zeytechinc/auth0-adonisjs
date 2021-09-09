/*
 * File: request.ts
 * Created Date: Aug 26, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare module '@ioc:Adonis/Core/Request' {
  interface RequestContract {
    auth?: any
    roles?: Array<string>
    userId?: string
    email?: string
    token?: string
    audience?: string | string[]
  }
}
