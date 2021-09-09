import { join } from 'path'
import * as sinkStatic from '@adonisjs/sink'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'

/**
 * Returns absolute path to the stub relative from the templates
 * directory
 */
function getStub(...relativePaths: string[]) {
  return join(__dirname, 'templates', ...relativePaths)
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
}
