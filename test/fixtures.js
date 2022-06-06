const fetch = require('node-fetch')
module.exports = {
  servers: [
    { name: 'express4', port: 33331 },
    { name: 'express5', port: 33332 },
    { name: 'fastify', port: 33333 },
    { name: 'node', port: 33334 },
    { name: 'spliffy', port: 33335 }
  ],
  basicAuth (user, pass) {
    return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`
  },
  async getJwtCookies(baseUrl, basicAuth){
    const res = await fetch(`${baseUrl}/login`, { headers: { Authorization: basicAuth } })
    expect(res.status).toBe(200)
    return res.headers.raw()['set-cookie']
  },
  toCookieHeader(cookies){
    return cookies.map(c=>`${c.split(';')[0]};`).join(' ')
  },
  getAuthCookie (setCookieHeader) {
    return setCookieHeader.find(it => it.match('jwt-auth'))
  },
  async getValidRefreshTokens(baseUrl){
    return (await fetch(`${baseUrl}/refreshTokens`)).json()
  },
  expectLogoutCookies(res){
    let rawHeaders = res.headers.raw()['set-cookie']
    const authCookie = rawHeaders.find(c => c.includes('jwt-auth'))
    const refreshCookie = rawHeaders.find(c => c.includes('jwt-refresh'))

    expect(authCookie).toBe('jwt-auth=; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
    expect(refreshCookie).toBe('jwt-refresh=; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
  }
}
