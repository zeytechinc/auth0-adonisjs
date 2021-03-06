/*
 * File: HealthCheckHelper.ts
 * Created Date: Aug 19, 2021
 * Copyright (c) 2021 Zeytech Inc. (https://zeytech.com)
 * Author: Steve Krenek (https://github.com/skrenek)
 * -----
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { DateTime, Duration } from 'luxon'
import { CacheLastAccessInfo } from '@ioc:Adonis/Addons/Zeytech/Auth0Service'

export default class HealthCheckHelper {
  private static format = 'yyyy-LL-dd HH:mm:ss ZZZZ'

  public static formatDateUtcAndTz(date: Date, tzName: string = 'America/Chicago'): string {
    const dt = DateTime.fromJSDate(date)
    return `${dt.toFormat(this.format)}|${dt.setZone(tzName).toFormat(this.format)}`
  }

  public static getAccessInfo(ms?: number, tzName?: string): CacheLastAccessInfo {
    if (!ms) {
      return {
        utc: 'never',
        localTz: 'never',
        age: -1,
        ageDesc: 'none',
      }
    }
    const date = DateTime.fromMillis(ms)
    const now = DateTime.utc()
    const age = Duration.fromMillis(now.toMillis() - date.toMillis())
    return {
      utc: date.toUTC().toFormat(this.format),
      localTz: date.setZone(tzName || 'America/Chicago').toFormat(this.format),
      age: age.as('milliseconds'),
      ageDesc: `${age.as('milliseconds')} ms (${age.as('minutes').toFixed(2)} min)`,
    }
  }
}
