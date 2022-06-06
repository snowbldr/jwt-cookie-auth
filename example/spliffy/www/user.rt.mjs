import { loadUserByUsername } from '../../authorizer.mjs'

export default {
  GET: ({ url: { query: { username } } }) => loadUserByUsername(username)
}
