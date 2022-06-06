const { servers, getAuthCookie, basicAuth, getJwtCookies } = require('./fixtures')
const fetch = require('node-fetch')

describe.each(servers)('rolecheck', (server) => {
  const baseUrl = `http://localhost:${server.port}`
  const url = path => `${baseUrl}${path}`
  describe(`${server.name} hasAnyRole`, () => {
    it(`${server} allows users with any of the roles to access the end point`, async () => {
      const jwtCookie = getAuthCookie( await getJwtCookies(baseUrl, basicAuth('taco', 'password123')))
      const res = await fetch(url('/secure/anyRole'), { headers: { Cookie: jwtCookie } })
      expect(res.status).toBe(200)
      expect(await res.text()).toEqual('taco')
      const jwtCookie1 = getAuthCookie( await getJwtCookies(baseUrl, basicAuth('donut', 'password321')))
      const res1 = await fetch(url('/secure/anyRole'), { headers: { Cookie: jwtCookie1 } })
      expect(res1.status).toBe(200)
      expect(await res1.text()).toEqual('donut')
    })
    it(`${server} denies users without the roles from using the end point`, async () => {
      const jwtCookie = getAuthCookie( await getJwtCookies(baseUrl, basicAuth('rando', 'password313')))
      const res = await fetch(url('/secure/anyRole'), { headers: { Cookie: jwtCookie } })
      expect(res.status).toBe(403)
    })
  })
  describe(`${server.name} hasAllRoles`, () => {
    it(`${server} allows users with all roles to access the end point`, async () => {
      const jwtCookie1 = getAuthCookie( await getJwtCookies(baseUrl, basicAuth('donut', 'password321')))
      const res1 = await fetch(url('/secure/allRoles'), { headers: { Cookie: jwtCookie1 } })
      expect(res1.status).toBe(200)
      expect(await res1.text()).toEqual('donut')
    })

    it(`${server} denies users with some matching roles to access the end point`, async () => {
      const jwtCookie = getAuthCookie( await getJwtCookies(baseUrl, basicAuth('taco', 'password123')))
      const res = await fetch(url('/secure/allRoles'), { headers: { Cookie: jwtCookie } })
      expect(res.status).toBe(403)
    })

    it(`${server} denies users with no matching roles to access the end point`, async () => {
      const jwtCookie = getAuthCookie( await getJwtCookies(baseUrl, basicAuth('rando', 'password313')))
      const res = await fetch(url('/secure/allRoles'), { headers: { Cookie: jwtCookie } })
      expect(res.status).toBe(403)
    })
  })
})
