import { loadUser } from '../../authorizer.mjs'

export default {
  GET: ({ url: { query: { username } } }) => loadUser(username)
}
