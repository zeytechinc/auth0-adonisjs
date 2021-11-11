import { join } from 'path'
import * as sinkStatic from '@adonisjs/sink'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'
import { readdirSync } from 'fs'

const configSettings = {
  localRoles: false,
}

/**
 * Returns absolute path to the stub relative from the templates
 * directory
 */
function getStub(...relativePaths: string[]) {
  return join(__dirname, 'templates', ...relativePaths)
}

/**
 * Moves template files and commits tem
 * @param projectRoot Project root path
 * @param templates Template configs
 */
function moveTemplates(
  projectRoot,
  templates: { path: string; stubFile: string }[],
  contents?: {}
) {
  for (let templateConfig of templates) {
    const template = new sinkStatic.files.MustacheFile(
      projectRoot,
      templateConfig.path,
      getStub(templateConfig.stubFile)
    )
    template.overwrite = true
    template.apply(contents).commit()
  }
}

/**
 * Checks if a database migration exists
 */
function checkMigrationExistence(migrationDir: string, migrationName: string): boolean {
  const contents = readdirSync(migrationDir)
  const regex = new RegExp(`^\\d+_${migrationName}.ts`)
  for (const filename of contents) {
    const matches = regex.test(filename)
    if (matches) {
      return true
    }
  }
  return false
}

function makeMigration(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic,
  migrationName
) {
  const migrationDir = app.directoriesMap.get('migrations') || 'database'
  const migrationPath = join(migrationDir, `${Date.now()}_${migrationName}.ts`)

  if (checkMigrationExistence(migrationDir, migrationName)) {
    sink.logger.action('create').skipped(`${migrationPath} file already exists`)
    return
  }

  const template = new sink.files.MustacheFile(
    projectRoot,
    migrationPath,
    getStub(`migrations/${migrationName}.txt`)
  )
  if (template.exists()) {
    sink.logger.action('create').skipped(`${migrationPath} file already exists`)
    return
  }

  template.commit()
  sink.logger.action('create').succeeded(migrationPath)
}

/**
 * Makes the auth config file
 */
async function makeController(
  projectRoot: string,
  _app: ApplicationContract,
  sink: typeof sinkStatic
) {
  const go = await sink
    .getPrompt()
    .confirm('Do you want me to generate a controller for Auth0 service calls?')
  if (go) {
    const controllerPath = join('app/Controllers/Http', 'Auth0Controller.ts')

    const template = new sink.files.MustacheFile(
      projectRoot,
      controllerPath,
      getStub('Auth0Controller.txt')
    )
    template.overwrite = true
    template.apply().commit()
    sink.logger.action('create').succeeded(controllerPath)
  } else {
    sink.logger.action('create').skipped('Not creating Auth0Controller')
  }
}

/**
 * Makes the roles files
 */
async function makeRoles(projectRoot: string, app: ApplicationContract, sink: typeof sinkStatic) {
  const go = await sink.getPrompt().confirm('Do you want to use Auth0 roles?', { default: true })
  if (!go) {
    makeMigration(projectRoot, app, sink, 'application_roles')
    makeMigration(projectRoot, app, sink, 'user_application_roles')

    const applicationRoleModelPath = join('app/Models', 'ApplicationRole.ts')
    const userApplicationRoleModelPath = join('app/Models', 'UserApplicationRole.ts')

    const templateConfigs = [
      {
        path: applicationRoleModelPath,
        stubFile: 'Models/ApplicationRole.txt',
      },
      {
        path: userApplicationRoleModelPath,
        stubFile: 'Models/UserApplicationRole.txt',
      },
    ]

    moveTemplates(projectRoot, templateConfigs)

    configSettings.localRoles = true

    sink.logger.action('roles').succeeded(templateConfigs.map((x) => x.path).join(', '))
  } else {
    sink.logger.action('roles').skipped('Not managing roles manually')
  }
}

/**
 * Makes the config file
 * @param projectRoot Project root
 * @param _app app
 * @param sink Sink
 */
async function makeConfig(
  projectRoot: string,
  _app: ApplicationContract,
  _sink: typeof sinkStatic
) {
  const configPath = join('config', 'zeytech-auth0.ts')

  const templateConfigs = [
    {
      path: configPath,
      stubFile: 'config.txt',
    },
  ]

  moveTemplates(projectRoot, templateConfigs, configSettings)
}

/**
 * Instructions to be executed when setting up the package.
 */
export default async function instructions(
  projectRoot: string,
  app: ApplicationContract,
  sink: typeof sinkStatic
) {
  /**
   * Make controller file
   */
  await makeController(projectRoot, app, sink)
  await makeRoles(projectRoot, app, sink)
  await makeConfig(projectRoot, app, sink)
}
