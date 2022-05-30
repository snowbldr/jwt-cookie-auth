import { hasAllRolesMiddleware } from 'jwt-cookie-auth'

export default {
  middleware: [hasAllRolesMiddleware('user', 'admin', 'donut eater')],
  GET: ({ req }) => req.user.username
}
