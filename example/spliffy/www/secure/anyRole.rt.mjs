import { hasAnyRoleMiddleware } from 'jwt-cookie-auth'

export default {
  middleware: [hasAnyRoleMiddleware('sauce boss', 'taco master', 'user')],
  GET: ({ req }) => req.user.username
}
