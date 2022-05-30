import { keyAuthorizer, loadUser } from '../authorizer.mjs'

export const authMiddleware = keyAuthorizer.authorizeMiddleware()

export const basicAuthLoginMiddleware = keyAuthorizer.basicAuthLoginMiddleware(loadUser)
