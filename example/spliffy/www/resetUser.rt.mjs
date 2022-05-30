import { loadUser } from '../../authorizer.mjs'

export default {
  GET: ({ url: { query: { username } } }) => {
    const user = loadUser(username)
    user.failedLogins = 0
    user.lockedAt = null
  }
}
