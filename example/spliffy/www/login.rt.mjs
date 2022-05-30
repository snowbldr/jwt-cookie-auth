import { basicAuthLoginMiddleware } from '../authMiddleware.mjs'

export default {
  middleware: [basicAuthLoginMiddleware],
  GET: ({ req }) => req.user
}
