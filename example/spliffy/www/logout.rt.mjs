import { keyAuthorizer } from '../../authorizer.mjs'

export default {
  middleware: [keyAuthorizer.logoutMiddleware()],
  GET: () => 'OK'
}
