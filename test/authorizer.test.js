const fetch = require('node-fetch')
const {
  servers,
  basicAuth,
  getAuthCookie,
  expectLogoutCookies,
  getJwtCookies,
  getValidRefreshTokens, toCookieHeader
} = require('./fixtures')
const { parse, serialize } = require('cookie')

const tacoBasicAuth = basicAuth('taco', 'password123')

async function validateJwtCookies (res, validateRefresh = true) {
  expect(res.status).toBe(200)
  const responseBody = await res.json()
  expect(responseBody).toEqual(expect.objectContaining({
    sub: 'taco',
    username: 'taco',
    roles: ['taco master', 'admin']
  }))
  const rawCookies = res.headers.raw()['set-cookie']
  const parsed = rawCookies.map(parse)
  validateCookie('jwt-auth', rawCookies.find(c => c.includes('jwt-auth')), parsed.find(p => 'jwt-auth' in p), responseBody, 3)
  if (validateRefresh) {
    validateCookie('jwt-refresh', rawCookies.find(c => c.includes('jwt-refresh')), parsed.find(p => 'jwt-refresh' in p), responseBody, 6)
  }
  return parsed.find(p => p['jwt-auth'])
}

function validateCookie (cookieName, rawCookie, parsed, expectedBody, expSeconds) {
  expect(rawCookie).toMatch('HttpOnly')
  expect(parsed.Path).toBe('/secure')
  expect(parsed['Max-Age']).toBe('10')
  const jwtPayload = JSON.parse(Buffer.from(parsed[cookieName].split('.')[1], 'base64').toString())
  expect(jwtPayload).toEqual(expect.objectContaining({
    aud: 'users',
    iss: 'jwt-authorizer',
    ...expectedBody
  }))
  const nowSeconds = Math.trunc(new Date().getTime() / 1000)
  expect(jwtPayload.iat).toBeGreaterThanOrEqual(nowSeconds - 1)
  expect(jwtPayload.exp).toBeLessThanOrEqual(nowSeconds + expSeconds + 3)
}

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
      await validateJwtCookies(res)
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
    it(`${server.name} accepts a jwt cookie for authentication and stores the refresh jwt`, async () => {
      const cookieHeader = await getJwtCookies(baseUrl, tacoBasicAuth)
      const res = await fetch(url('/secure/secrets'), { headers: { Cookie: getAuthCookie(cookieHeader) } })
      expect(res.status).toBe(200)
      expect(await res.text()).toEqual('taco')
      const refreshCookie = parse(cookieHeader.find(h => h.includes('jwt-refresh')))
      const validRefreshTokens = await getValidRefreshTokens(baseUrl)
      expect(validRefreshTokens[refreshCookie['jwt-refresh']]).toBe('taco')
    })
    it(`${server.name} does not accept JWT as authorization`, async () => {
      const res = await fetch(url('/secure/secrets'), { headers: { Authorization: getAuthCookie(await getJwtCookies(baseUrl, tacoBasicAuth)) } })
      expect(res.status).toBe(401)
    })
    it(`${server.name} does not accept invalid JWTs`, async () => {
      const badCookie = serialize('jwt-auth', '1234abcdef', {
        maxAge: 60 * 60, // 1 hour
        secure: false,
        httpOnly: true
      })
      const res = await fetch(url('/secure/secrets'), { headers: { Cookie: badCookie } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Invalid Jwt')
    })
    it(`${server.name} does not accept expired JWTs`, async () => {
      const jwtCookie = getAuthCookie(await getJwtCookies(baseUrl, tacoBasicAuth))
      console.log('waiting for token to expire...')
      await new Promise((resolve, reject) => setTimeout(() => {
        fetch(url('/secure/secrets'), { headers: { Cookie: jwtCookie } })
          .then(res => {
            expect(res.status).toBe(401)
            res.text().then(body => {
              expect(body).toMatch('Invalid Jwt')
              expectLogoutCookies(res)
              resolve()
            })
          }).catch(reject)
      }, 3500))
    }, 5000)
  })
  describe('logout', () => {
    it(`${server.name} deletes the auth cookies on logout and invalidates the refresh token`, async () => {
      const jwtCookies = await getJwtCookies(baseUrl, tacoBasicAuth)
      const res = await fetch(url('/logout'), { headers: { Cookie: toCookieHeader(jwtCookies) } })
      const refreshCookie = parse(jwtCookies.find(h => h.includes('jwt-refresh')))
      const validRefreshTokens = await getValidRefreshTokens(baseUrl)
      expect(validRefreshTokens[refreshCookie['jwt-refresh']]).toBe(undefined)
      expect(res.status).toBe(200)
      expect(await res.text()).toEqual('OK')
      expectLogoutCookies(res)
    })
  })
  describe('refresh', () => {
    it(`${server.name} refreshes a valid jwt`, async () => {
      const initJwtCookie = await getJwtCookies(baseUrl, tacoBasicAuth)
      const refreshCookie = parse(initJwtCookie.find(h => h.includes('jwt-refresh')))
      const validRefreshTokens = await getValidRefreshTokens(baseUrl)
      expect(validRefreshTokens[refreshCookie['jwt-refresh']]).toBe('taco')
      const initAuthCookie = parse(getAuthCookie(initJwtCookie))

      const cookieHeader = toCookieHeader(initJwtCookie)
      // wait 1 second so the jwt will have a different value
      await new Promise((resolve) => setTimeout(resolve, 1050))
      const res = await fetch(url('/refresh'), { headers: { Cookie: cookieHeader } })
      const cookie = await validateJwtCookies(res, false)
      expect(initAuthCookie).not.toEqual(cookie)
    })
    it(`${server.name} does not refresh if the refreshJwt is invalid`, async () => {
      const initJwtCookie = await getJwtCookies(baseUrl, tacoBasicAuth)
      const cookieHeader = toCookieHeader(initJwtCookie.map(h => {
        if (h.includes('jwt-refresh')) {
          return h.replace(/jwt-refresh=.*;/, 'jwt-refresh=taco;')
        } else {
          return h
        }
      }))
      const res = await fetch(url('/refresh'), { headers: { Cookie: cookieHeader } })
      expect(res.status).toBe(401)
      expectLogoutCookies(res)
    })
    it(`${server.name} does not refresh an expired jwt`, async () => {
      const initJwtCookie = await getJwtCookies(baseUrl, tacoBasicAuth)
      const refreshCookie = parse(initJwtCookie.find(h => h.includes('jwt-refresh')))
      const validRefreshTokens = await getValidRefreshTokens(baseUrl)
      expect(validRefreshTokens[refreshCookie['jwt-refresh']]).toBe('taco')
      const cookieHeader = toCookieHeader(initJwtCookie)
      // wait 1 second so the jwt will have a different value
      await new Promise((resolve) => setTimeout(resolve, 3500))
      const res = await fetch(url('/refresh'), { headers: { Cookie: cookieHeader } })
      expect(res.status).toBe(401)
      expectLogoutCookies(res)
    })
    it(`${server.name} does not refresh if missing jwt cookie`, async () => {
      const initJwtCookie = await getJwtCookies(baseUrl, tacoBasicAuth)
      const cookieHeader = toCookieHeader(initJwtCookie.filter(h => !h.includes('jwt-auth')))
      const res = await fetch(url('/refresh'), { headers: { Cookie: cookieHeader } })
      expect(res.status).toBe(401)
      expectLogoutCookies(res)
    })
    it(`${server.name} does not refresh if missing refresh cookie`, async () => {
      const initJwtCookie = await getJwtCookies(baseUrl, tacoBasicAuth)
      const cookieHeader = toCookieHeader(initJwtCookie.filter(h => !h.includes('jwt-refresh')))
      const res = await fetch(url('/refresh'), { headers: { Cookie: cookieHeader } })
      expect(res.status).toBe(401)
      expectLogoutCookies(res)
    })
  })
})
