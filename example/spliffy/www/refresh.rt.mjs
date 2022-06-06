import { keyAuthorizer } from '../../authorizer.mjs'

export default {
  middleware: [keyAuthorizer.refreshAuthMiddleware(true)],
  GET: ({req}) => req.user
}