import { keyAuthorizer } from '../authorizer.mjs'

export const authMiddleware = keyAuthorizer.authorizeMiddleware()

export const basicAuthLoginMiddleware = keyAuthorizer.basicAuthLoginMiddleware()
