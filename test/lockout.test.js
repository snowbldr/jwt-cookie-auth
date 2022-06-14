const { servers, basicAuth } = require('./fixtures.cjs')
const fetch = require('node-fetch')

describe.each(servers)('lockout', (server) => {
  const baseUrl = `http://localhost:${server.port}`
  const url = path => `${baseUrl}${path}`
  beforeEach(async () => {
    await fetch(url('/resetUser?username=lockme'))
  })
  it(`${server.name} failed login count is incremented when there's a failed login`, async () => {
    const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('lockme', 'notit') } })
    expect(res.status).toBe(401)
    expect(await res.text()).toMatch('Login Failed')
    const userRes = await fetch(url('/user?username=lockme'))
    const lockme = await userRes.json()
    expect(lockme.failedLogins).toBe(1)
  })
  it(`${server.name} user gets locked out after too many attempts`, async () => {
    for (let i = 0; i < 2; i++) {
      const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('lockme', 'notit') } })
      expect(res.status).toBe(401)
      expect(await res.text()).toMatch('Login Failed')
    }
    const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('lockme', 'notit') } })
    expect(res.status).toBe(401)
    expect(await res.text()).toMatch('user locked')
    const lockme = await (await fetch(url('/user?username=lockme'))).json()
    expect(lockme.failedLogins).toBe(3)
    expect(new Date(lockme.lockedAt).getTime()).toBeLessThanOrEqual(new Date().getTime())
  })
  it(`${server.name} lockout expires and user can log in successfully after lockout`, async () => {
    for (let i = 0; i < 4; i++) {
      const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('lockme', 'notit') } })
      expect(res.status).toBe(401)
    }
    await new Promise((resolve) => setTimeout(resolve, 3000))
    const res = await fetch(url('/login'), { headers: { Authorization: basicAuth('lockme', 'password333') } })
    expect(res.status).toBe(200)
    const response = await res.json()
    expect(response).toEqual({ sub: 'lockme', username: 'lockme', roles: ['gun get locked'] })
    const lockme = await (await fetch(url('/user?username=lockme'))).json()
    expect(lockme.failedLogins).toBe(0)
    expect(lockme.lockedAt).toBe(null)
  })
})
