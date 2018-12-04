'use strict'

const functions = require('firebase-functions')
const crypto = require('crypto')
const secureCompare = require('secure-compare')
const mqtt = require('mqtt')

/*
  mqtt.port
  mqtt.host
  mqtt.user
  mqtt.password
  github.secret
 */
exports.hook = functions.https.onRequest((req, res) => {
  const cipher = 'sha1'
  const signature = req.headers['X-Hub-Signature']
  const hmac = crypto.createHmac(cipher, functions.config().github.secret).update(req.body).digest('hex')
  const expectedSignature = `${cipher}=${hmac}`
  if (!secureCompare(signature, expectedSignature)) {
    console.error('x-hub-signature', signature, 'did not match', expectedSignature)
    res.status(403).send('Your x-hub-signature\'s bad and you should feel bad!')
    return
  }

  const event = req.headers['X-GitHub-Event']
  const topic = '/GhWebhook/' + req.body.repository.full_name + '/' + event
  let message = ''

  switch (event) {
    case 'push':
      message = 'ref:' + req.body.ref
      break
  }

  const options = {
    port: functions.config().mqtt.port,
    host: functions.config().mqtt.host,
    clientId: 'GhWebhookToMQTT',
    username: functions.config().mqtt.user,
    password: functions.config().mqtt.password,
    clean: true
  }
  const client = mqtt.connect(functions.config().mqtt.host, options)
  client.on('connect', () => console.log('client connected'))
  client.on('error', err => console.error(err))

  console.log('topic: ' + topic)
  console.log('message: ' + message)

  client.publish(topic, message, err => {
    if (err) {
      console.log('Error:' + err)
      res.status(500).send('Error:' + err)
      return
    }
    res.sendStatus(204)
    client.end()
  })
})
