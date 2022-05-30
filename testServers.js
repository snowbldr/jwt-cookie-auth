const path = require('path')
const childProcess = require('child_process')
const { servers } = require('./test/fixtures')

const processes = []

module.exports = {
  start: async () => {
    console.log()
    console.log('Installing dependencies')
    await Promise.all(servers.map(server => new Promise((resolve, reject) => {
      const serverPath = path.resolve(__dirname, 'example', server.name)
      const install = childProcess.exec('npm i', { cwd: serverPath, stdio: 'inherit' })
      install.on('exit', (code) => {
        if (code === 0) resolve()
        else reject(new Error(`npm install for server ${server.name} exited with exit code ${code}`))
      })
    })
    ))
    return new Promise((resolve, reject) => {
      console.log('Starting servers')
      // for (const server of servers.map(server=>server.name)) {
      for (const server of servers.map(server => server.name)) {
        console.log(`Starting: ${server}`)
        const timeout = 5_000
        const rejectTimeout = setTimeout(() => {
          reject(new Error(`Server ${server} was not initialized within ${timeout}ms`))
        }, timeout)
        const serverProcess = childProcess.spawn('node', [path.resolve(__dirname, 'example', server, 'index.mjs')])
        serverProcess.on('error', err => {
          console.log(`got error from ${server} server`, err)
          clearTimeout(rejectTimeout)
          reject(err)
        })
        serverProcess.on('exit', (code) => {
          clearTimeout(rejectTimeout)
          if (code === 0) {
            resolve()
          } else {
            reject(new Error(`Server ${server} exited with status: ${code}`))
          }
        })
        serverProcess.stdout.setEncoding('utf-8')
        serverProcess.stdout.on('data', data => {
          console.log(data)
          if (data.match('Server initialized')) {
            clearTimeout(rejectTimeout)
            resolve()
          }
        })
        serverProcess.stderr.setEncoding('utf-8')
        serverProcess.stderr.on('data', console.error)
        processes.push(serverProcess)
      }
    })
  },
  stop: async () => processes.forEach(server => server.kill())
}
