import spliffy from '@srfnstack/spliffy'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

spliffy({ port: 33335, routeDir: join(dirname(fileURLToPath(import.meta.url)), 'www') })
