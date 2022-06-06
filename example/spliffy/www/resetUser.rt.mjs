import { loadUserByUsername } from '../../authorizer.mjs'

export default {
  GET: ({ url: { query: { username } } }) => {
    const user = loadUserByUsername(username)
    user.failedLogins = 0
    user.lockedAt = null
  }
}
