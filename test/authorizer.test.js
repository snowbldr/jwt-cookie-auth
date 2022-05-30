const fetch = require('node-fetch')
const { servers, basicAuth, getJwtCookie } = require('./fixtures')
const { parse, serialize } = require('cookie')

const tacoBasicAuth = basicAuth('taco', 'password123')

describe.each(servers)('authorizer', (server) => {
  const baseUrl = `http://localhost:${server.port}`
  const url = path => `${baseUrl}${path}`
  it(`${server.name} is healthy`, async () => {
    const res = await fetch(url('/health'))
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('OK')
  })
  describe('login', () => {
    it(`${server.name} returns a 401 if no basic auth header is provided`, async () => {
      const res = await fetch(url('/login'))
      expect(res.status).toBe(401)
    })
    it(`${server.name} exchanges a basic auth header for a jwt`, async () => {
      const res = await fetch(url('/login'), { headers: { Authorization: tacoBasicAuth } })
      expect(res.status).toBe(200)
      const response = await res.json()
      expect(response).toEqual({ sub: 'taco', username: 'taco', roles: ['taco master', 'admin'] })
      const rawCookie = res.headers.raw()['set-cookie'][0]
      expect(rawCookie).toMatch('HttpOnly')
      const jwtCookie = parse(rawCookie)
      expect(jwtCookie.Path).toBe('/secure')
      expect(jwtCookie['Max-Age']).toBe('60')
      const jwtPayload = JSON.parse(Buffer.from(jwtCookie['jwt-session'].split('.')[1], 'base64').toString())
      expect(jwtPayload).toEqual(expect.objectContaining({
        aud: 'users',
        iss: 'jwt-authorizer',
        ...response
      }))
      const nowSeconds = Math.trunc(new Date().getTime() / 1000)
      expect(jwtPayload.iat).toBeGreaterThanOrEqual(nowSeconds - 1)
      expect(jwtPayload.iat).toBeLessThanOrEqual(nowSeconds + 10)
    })
    it(`${server.name} doesn't accept an unknown user`, async () => {
      const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('ur mudda', 'pass') } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Login Failed')
    })
    it(`${server.name} doesn't accept an invalid password`, async () => {
      const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('taco', 'passwordo') } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Login Failed')
    })
    it(`${server.name} doesn't accept unencoded basic auth header`, async () => {
      const res = await fetch(url('/login'), { headers: { Authorization: 'Basic taco:password123' } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Login Failed')
    })
    it(`${server.name} doesn't accept an empty password`, async () => {
      const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('taco', '') } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Login Failed')
    })
    it(`${server.name} doesn't accept an empty username`, async () => {
      const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('', 'password123') } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Login Failed')
    })
    it(`${server.name} doesn't accept a malformed basic auth header`, async () => {
      const res = await fetch(url('/login'), { headers: { Authorization: ' user:taco, pass:password123' } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Basic Authorization header must be used')
    })
  })
  describe('authorize', () => {
    it(`${server.name} returns a 401 if no jwt cookie is provided`, async () => {
      const res = await fetch(url('/secure/secrets'))
      expect(res.status).toBe(401)
    })
    it(`${server.name} accepts a jwt cookie for authentication`, async () => {
      const res = await fetch(url('/secure/secrets'), { headers: { Cookie: await getJwtCookie(baseUrl, tacoBasicAuth) } })
      expect(res.status).toBe(200)
      expect(await res.text()).toEqual('taco')
    })
    it(`${server.name} does not accept JWT as authorization`, async () => {
      const res = await fetch(url('/secure/secrets'), { headers: { Authorization: await getJwtCookie(baseUrl, tacoBasicAuth) } })
      expect(res.status).toBe(401)
    })
    it(`${server.name} does not accept invalid JWTs`, async () => {
      const badCookie = serialize('jwt-session', '1234abcdef', {
        maxAge: 60 * 60, // 1 hour
        secure: false,
        httpOnly: true
      })
      const res = await fetch(url('/secure/secrets'), { headers: { Cookie: badCookie } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Invalid Jwt')
    })
    it(`${server.name} does not accept expired JWTs`, async () => {
      const jwtCookie = await getJwtCookie(baseUrl, tacoBasicAuth)
      console.log('waiting for token to expire...')
      await new Promise((resolve, reject) => setTimeout(() => {
        fetch(url('/secure/secrets'), { headers: { Cookie: jwtCookie } })
          .then(res => {
            expect(res.status).toBe(401)
            res.text().then(body => {
              expect(body).toMatch('Invalid Jwt')
              resolve()
            })
          }).catch(reject)
      }, 3500))
    }, 5000)
  })
})
