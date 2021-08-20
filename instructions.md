The package has been configured successfully.

Open the env.ts file and paste the following code inside the Env.rules object.

```ts
AUTH0_CLIENT_ID: Env.schema.string(),
AUTH0_CLIENT_SECRET: Env.schema.string(),
AUTH0_DOMAIN: Env.schema.string(),
AUTH0_AUDIENCE: Env.schema.string(),
AUTH0_SCOPE: Env.schema.string.optional(),
AUTH_CERT: Env.schema.string.optional(),
```
