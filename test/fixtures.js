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
  async getJwtCookie (baseUrl, basicAuth) {
    const res = await fetch(`${baseUrl}/login`, { headers: { Authorization: basicAuth } })
    expect(res.status).toBe(200)
    return res.headers.raw()['set-cookie'][0]
  }
}
