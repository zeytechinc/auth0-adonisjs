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
