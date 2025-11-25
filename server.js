require('dotenv').config()
const net = require('net')
const axios = require('axios')
const crypto = require('crypto')
const uWS = require('uWebSockets.js')
const admin = require('firebase-admin')


const DATABASE_URL = process.env.DATABASE_URL
const DATA_PATH = process.env.DATA_PATH
const SIGNATURE = process.env.SIGNATURE
const PROJECT_ID = process.env.PROJECT_ID
const API_KEY = process.env.API_KEY
const CERT = process.env.CERT
const GMP_ID = process.env.GMP_ID
const CLIENT = process.env.CLIENT
const PORT = process.env.PORT || 9099
const VERSION = 'Android/Fallback/X24000001/FirebaseCore-Android'
const PACKAGE = 'com.rr.bubtbustracker'

let SCHEDULE = null
let LOCATION = null
let BUS_MAP = null
let BUS_STATUS = {}
let BUS_LOCATION = {}
let mStart = new Date().toString()



let serviceAccount = {
    type: process.env.TYPE,
    project_id: process.env.PROJECT_ID,
    private_key_id: process.env.PRIVATE_KEY_ID,
    private_key: process.env.PRIVATE_KEY.replace(/\\n/g, '\n'),
    client_email: process.env.CLIENT_EMAIL,
    client_id: process.env.CLIENT_ID,
    auth_uri: process.env.AUTH_URI,
    token_uri: process.env.TOKEN_URI,
    auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.CLIENT_X509_CERT_URL
}

let KEY = Buffer.from(process.env.AES_KEY.split(',').map(n => parseInt(n.trim())))
let IV = Buffer.from(process.env.AES_IV.split(',').map(n => parseInt(n.trim())))

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: DATABASE_URL
})

const database = admin.database()
const messaging = admin.messaging()
const tester = net.createServer()

tester.once('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.log(`Port ${PORT} is already in use. Server not started.`)
        process.exit(1)
    }
})

tester.once('listening', () => {
    tester.close()

    const app = uWS.App()

    app.ws('/*', {
        compression: uWS.SHARED_COMPRESSOR,
        maxPayloadLength: 64 * 1024 * 1024,
        idleTimeout: 0,

        message: (ws, message, isBinary) => {
            try {
                let msgStr = isBinary ? Buffer.from(message) : Buffer.from(message).toString()

                if (!isBinary) {
                    let data = JSON.parse(msgStr)
                    let { t, s, lat, lng } = data

                    if (t === 1 && s) {
                        ws.subscribe(s)
                        let d = BUS_LOCATION[s]
                        if (d && d.data && d.data.length > 0) {
                            let last = d.data[d.data.length - 1]
                            let status = BUS_STATUS[s] || false
                            ws.send(JSON.stringify({ t: 1, id:d.id, s: status, lat:last.lat, lng:last.lng, time: last.time, from:d.from, to:d.to }))
                        } else {
                            ws.send(JSON.stringify({ t: 1, s: false }))
                        }
                    } else if (t === 2 && s) {
                        ws.unsubscribe(s)
                    } else if (t === 3 && s && lat && lng) {
                        if (BUS_STATUS[s]) {
                            let time = Date.now()
                            let d = BUS_LOCATION[s]
                            if (d && d.data) {
                                d.data.push({ lat, lng, time })
                            }
                            app.publish(s, JSON.stringify({ t: 2, lat, lng, time }))
                        }
                    } else if (t === 4) {
                        let d = BUS_LOCATION[s]
                        if (d) {
                            let list = d.data
                            if (list) {
                                let time = data.time
                                if (time == 0) {
                                    ws.send(JSON.stringify({ t: 3, data:list }))
                                } else if (time) {
                                    let filter = list.filter(item => item.time > time)
                                    ws.send(JSON.stringify({ t: 3, data:filter }))
                                } else {
                                    ws.send(JSON.stringify({ t: 3, data:[] }))
                                }
                            } else {
                                ws.send(JSON.stringify({ t: 3, data:[] }))
                            }
                        } else {
                            ws.send(JSON.stringify({ t: 3, data:[] }))
                        }
                    }
                }
            } catch (error) {}
        },

        close: (ws, code, message) => {}
    })


    app.post('/notification', async (res, req) => {
        res.writeHeader('Content-Type', 'application/json')
        res.onAborted(() => {})

        try {
            const { title, body, data, token, bus } = await getBody(res)

            if (!title || !body || !token || !bus) {
                return res.end(JSON.stringify({ status: 'FIELD_EMPTY' }))
            }

            let validToken = await verifyToken(decrypt(token))

            if (!validToken) {
                return res.end(JSON.stringify({ status: 'ERROR' }))
            }

            await messaging.send({
                notification: { title, body },
                data: data || {},
                topic: bus
            })
            return res.end(JSON.stringify({ status: 'SUCCESS' }))
        } catch (err) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }
    })

    app.post('/login', async (res, req) => {
        res.writeHeader('Content-Type', 'application/json')
        res.onAborted(() => {})

        let { email, password, token } = await getBody(res)

        if (!email || !password || !token) {
            return res.end(JSON.stringify({ status: 'FIELD_EMPTY' }))
        }

        if (!email.includes('@') || email.indexOf('@') > email.lastIndexOf('.')) {
            return res.end(JSON.stringify({ status: 'WRONG_EMAIL' }))
        }

        password = decrypt(password)

        if (!password) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        if (password.length < 6) {
            return res.end(JSON.stringify({ status: 'PASSWORD_LENGTH_SHORT' }))
        }

        let validToken = await verifyToken(decrypt(token))

        if (!validToken) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        let result = 'LOGIN_FAILED'

        try {
            let response = await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key='+API_KEY, { 'email': email, 'password': password, 'returnSecureToken': true, 'clientType': 'CLIENT_TYPE_ANDROID' }, { headers: getHeaders() })

            let refreshToken = response.data.refreshToken
            let idToken = response.data.idToken

            if (refreshToken && idToken) {
                try {
                    response = await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key='+API_KEY, { 'idToken': idToken }, { headers: getHeaders() })

                    if (response.data.kind.includes('GetAccountInfoResponse')) {
                        let users = response.data.users
                        let emailVerified = users[0].emailVerified
                        let localId = users[0].localId

                        response = await axios.get(DATABASE_URL+'/'+DATA_PATH+'/'+localId+'.json')
                        let data = response.data
                        if (data) {
                            return res.end(JSON.stringify({
                                status: 'SUCCESS',
                                role: data.role,
                                name: data.name,
                                bus: data.bus,
                                id: localId,
                                verified: emailVerified,
                                passwordUpdatedAt: users[0].passwordUpdatedAt,
                                lastLoginAt: users[0].lastLoginAt,
                                createdAt: users[0].createdAt,
                                refreshToken: refreshToken,
                                accessToken: idToken,
                                schedule: JSON.stringify(SCHEDULE),
                                requestToken: encrypt(API_KEY+'|'+CERT+'|'+GMP_ID+'|'+CLIENT+'|'+PROJECT_ID)
                            }))
                        }
                    }
                } catch (error) {}
            }
        } catch (error) {
            result = 'ERROR'
            try {
                if (error.response && error.response.data) {
                    let msg = error.response.data.error.message
                    if (msg == 'INVALID_LOGIN_CREDENTIALS') {
                        result = 'LOGIN_FAILED'
                    } else if (msg == 'INVALID_EMAIL') {
                        result = 'INVALID_EMAIL'
                    }
                }
            } catch (error) {}
        }
        return res.end(JSON.stringify({ status: result }))
    })


    app.post('/reset', async (res, req) => {
        res.writeHeader('Content-Type', 'application/json')
        res.onAborted(() => {})

        let { email, token } = await getBody(res)

        if (!email || !token) {
            return res.end(JSON.stringify({ status: 'FIELD_EMPTY' }))
        }

        if (!email.includes('@') || email.indexOf('@') > email.lastIndexOf('.')) {
            return res.end(JSON.stringify({ status: 'WRONG_EMAIL' }))
        }

        let validToken = await verifyToken(decrypt(token))

        if (!validToken) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        try {
            await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key='+API_KEY, { 'requestType': 1, 'email': email, androidInstallApp: false, canHandleCodeInApp: false, 'clientType': 'CLIENT_TYPE_ANDROID' }, { headers: getHeaders() })
            return res.end(JSON.stringify({ status: 'SUCCESS' }))
        } catch (error) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }
    })


    app.post('/verification', async (res, req) => {
        res.writeHeader('Content-Type', 'application/json')
        res.onAborted(() => {})

        let authHeader = req.getHeader('authorization') || req.getHeader('Authorization')
        let { accessToken, token } = await getBody(res)

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.end(JSON.stringify({ status: 'NO_HEADER_TOKEN' }))
        }

        let refreshToken = authHeader.split(' ')[1]

        if (!refreshToken || refreshToken.length < 10) {
            return res.end(JSON.stringify({ status: 'NO_HEADER_TOKEN' }))
        }

        if (!token) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        let validToken = await verifyToken(decrypt(token))

        if (!validToken) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        let latestToken = null

        if (!accessToken) {
            latestToken = await getAccessToken(refreshToken, null)
            accessToken = latestToken
        }

        if (!accessToken) {
            return res.end(JSON.stringify({ status: 'NO_ACCESS_TOKEN' }))
        }

        let result = 'ERROR'

        for (let i = 0; i < 2; i++) {
            try {
                let response = await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key='+API_KEY, { 'idToken': accessToken }, { headers: getHeaders() })

                if (response.data.kind.includes('GetAccountInfoResponse')) {
                    let users = response.data.users
                    let emailVerified = users[0].emailVerified
                    let localId = users[0].localId

                    try {
                        if (Math.floor((Date.now() - new Date(users[0].lastRefreshAt).getTime()) / (1000 * 60)) > 45) {
                            latestToken = await getAccessToken(refreshToken, accessToken)
                            accessToken = latestToken
                        }
                    } catch (error) {}

                    try {
                        await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key='+API_KEY, { 'requestType': 4, 'idToken': accessToken, 'clientType': 'CLIENT_TYPE_ANDROID' }, { headers: getHeaders() })
                    } catch (error) {}

                    return res.end(JSON.stringify({
                        status: 'SUCCESS',
                        id: localId,
                        verified:emailVerified,
                        passwordUpdatedAt: users[0].passwordUpdatedAt,
                        lastLoginAt: users[0].lastLoginAt,
                        createdAt: users[0].createdAt,
                        latestToken: latestToken,
                        schedule: JSON.stringify(SCHEDULE)
                    }))
                }
            } catch (error) {
                result = 'ERROR'
                try {
                    if (error.response && error.response.data) {
                        let msg = error.response.data.error.message

                        if (msg == 'INVALID_ID_TOKEN' || msg == 'TOKEN_EXPIRED') {
                            latestToken = await getAccessToken(refreshToken, accessToken)
                            accessToken = latestToken
                            continue
                        }
                    }
                } catch (error) {}
            }

            break
        }

        return res.end(JSON.stringify({ status: result }))
    })


    app.post('/sign_up', async (res, req) => {
        res.writeHeader('Content-Type', 'application/json')
        res.onAborted(() => {})

        let { email, password, name, bus, token } = await getBody(res)

        if (!email || !password || !name || !bus || !token) {
            return res.end(JSON.stringify({ status: 'FIELD_EMPTY' }))
        }

        if (!email.includes('@') || email.lastIndexOf('@') > email.lastIndexOf('.')) {
            return res.end(JSON.stringify({ status: 'WRONG_EMAIL' }))
        }

        password = decrypt(password)

        if (!password) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        if (password.length < 6) {
            return res.end(JSON.stringify({ status: 'PASSWORD_LENGTH_SHORT' }))
        }

        let validToken = await verifyToken(decrypt(token))

        if (!validToken) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        let result = 'SING_UP_FAILED'

        try {
            let response = await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key='+API_KEY, { 'email': email, 'password': password, 'clientType': 'CLIENT_TYPE_ANDROID' }, { headers: getHeaders() })


            if (response.data.kind.includes('SignupNewUserResponse')) {
                let refreshToken = response.data.refreshToken
                let idToken = response.data.idToken
                let localId = response.data.localId

                try {
                    await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key='+API_KEY, { 'requestType': 4, 'idToken': idToken, 'clientType': 'CLIENT_TYPE_ANDROID' }, { headers: getHeaders() })
                } catch (error) {}

                await database.ref(DATA_PATH).child(localId).update({ role: 'STUDENT', email, name,  bus })

                return res.end(JSON.stringify({
                    status: 'SUCCESS',
                    id: localId,
                    refreshToken: refreshToken,
                    accessToken: idToken,
                    schedule: JSON.stringify(SCHEDULE),
                    requestToken: encrypt(API_KEY+'|'+CERT+'|'+GMP_ID+'|'+CLIENT+'|'+PROJECT_ID)
                }))
            }
        } catch (error) {
            result = 'ERROR'
            try {
                if (error.response && error.response.data) {
                    let msg = error.response.data.error.message
                    if (msg == 'EMAIL_EXISTS') {
                        result = 'EMAIL_EXISTS'
                    } else if (msg == 'INVALID_EMAIL') {
                        result = 'INVALID_EMAIL'
                    }
                }
            } catch (error) {}

        }
        return res.end(JSON.stringify({ status: result }))
    })

    app.post('/bus_change', async (res, req) => {
        res.writeHeader('Content-Type', 'application/json')
        res.onAborted(() => {})

        let { id, bus, token } = await getBody(res)

        if (!id || !bus || !token) {
            return res.end(JSON.stringify({ status: 'FIELD_EMPTY' }))
        }

        let validToken = await verifyToken(decrypt(token))

        if (!validToken) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        try {
            await database.ref(DATA_PATH).child(id).update({ bus : bus })

            return res.end(JSON.stringify({ status: 'SUCCESS' }))
        } catch (error) {}

        return res.end(JSON.stringify({ status: 'ERROR' }))
    })

    app.post('/start_trip', async (res, req) => {
        res.writeHeader('Content-Type', 'application/json')
        res.onAborted(() => {})

        let { bus, lat, lng, token } = await getBody(res)

        if (!bus || !token) {
            return res.end(JSON.stringify({ status: 'FIELD_EMPTY' }))
        }

        let validToken = await verifyToken(decrypt(token))

        if (!validToken) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        try {
            let result = detectLocation(lat, lng)
            let title = '🚌 BUBT Bus is on the Way!'
            let from = result
            let to = 'BUBT'
            let body = `Bus started from ${result} and going to BUBT.`
            if (result === 'BUBT') {
                from = 'BUBT'
                to = BUS_MAP[bus]
                body = `Bus started from BUBT and going to ${to}.`
            }

            let time = Date.now()
            BUS_LOCATION[bus] = { id:time, from, to, data: [ { lat, lng, time }] }
            BUS_STATUS[bus] = true

            app.publish(bus, JSON.stringify({ t:1, id:time, s:true, lat, lng, time, from, to }))

            await messaging.send({
                notification: { title, body },
                data: {},
                topic: bus
            })

            return res.end(JSON.stringify({ status: 'SUCCESS' }))
        } catch (error) {}

        return res.end(JSON.stringify({ status: 'ERROR' }))
    })

    app.post('/stop_trip', async (res, req) => {
        res.writeHeader('Content-Type', 'application/json')
        res.onAborted(() => {})

        let { bus, token } = await getBody(res)

        if (!bus || !token) {
            return res.end(JSON.stringify({ status: 'FIELD_EMPTY' }))
        }

        let validToken = await verifyToken(decrypt(token))

        if (!validToken) {
            return res.end(JSON.stringify({ status: 'ERROR' }))
        }

        try {
            delete BUS_LOCATION[bus]
            BUS_STATUS[bus] = false

            app.publish(bus, JSON.stringify({ t:1, s:false }))

            return res.end(JSON.stringify({ status: 'SUCCESS' }))
        } catch (error) {}

        return res.end(JSON.stringify({ status: 'ERROR' }))
    })

    app.get('/schedule', (res, req) => {
        res.writeHeader('Content-Type', 'application/json')

        if(SCHEDULE) {
            res.end(JSON.stringify({
                status: 200,
                data: SCHEDULE
            }))
        } else {
            res.end(JSON.stringify({
                status: 400
            }))
        }
    })

    app.get('/', (res, req) => res.end('' + mStart))

    app.listen(PORT, (listenSocket) => {
        if (listenSocket) console.log(`BusTracker server running on port ${PORT}`)
    })
})

tester.listen(PORT)


startProcess()

async function startProcess() {
    try {
        let response = await axios.get(DATABASE_URL+'/'+DATA_PATH.substring(0, 6)+'schedule.json')
        SCHEDULE = response.data
        LOCATION = getLocationData()
        BUS_MAP = getBusMapData()
    } catch (error) {}
}

function getLocationData() {
    let result = {}

    SCHEDULE.forEach(busRoute => {
        let routes = busRoute.r
        for (let key in routes) {
            let route = routes[key]
            let name = route.n
            let locations = route.l

            let locWith1 = locations.find(loc => loc.trim().endsWith(',1'))

            if (locWith1) {
                result[name] = locWith1.replace(/,1$/, '')
            }
        }
    })

    return result
}

function getBusMapData() {
    let busMap = {}

    SCHEDULE.forEach(busRoute => {
        let busName = busRoute.n.toUpperCase()
        let firstRouteKey = Object.keys(busRoute.r)[0]
        let firstRoute = busRoute.r[firstRouteKey]
        if (firstRoute && firstRoute.n) {
            busMap[busName] = firstRoute.n
        }
    })

    return busMap
}

function getDistanceMeters(lat1, lng1, lat2, lng2) {
    let toRad = deg => deg * Math.PI / 180
    let R = 6371000
    let dLat = toRad(lat2 - lat1)
    let dLng = toRad(lng2 - lng1)
    let a = Math.sin(dLat/2)**2 + Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLng/2)**2
    let c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a))
    return R * c
}


function detectLocation(inputLat, inputLng, radiusMeters = 250) {
    for (let [name, coord] of Object.entries(LOCATION)) {
        let [latStr, lngStr] = coord.split(',')
        let lat = parseFloat(latStr)
        let lng = parseFloat(lngStr)
        let distance = getDistanceMeters(inputLat, inputLng, lat, lng)
        if (distance <= radiusMeters) {
            return name
        }
    }
    return 'Unknown Location'
}

async function getAccessToken(token, accessToken) {
    try {
        let response = await axios.post('https://securetoken.googleapis.com/v1/token?key='+API_KEY, { 'grantType': 'refresh_token', 'refreshToken': token }, { headers: getHeaders() })
        return response.data.access_token
    } catch (error) {
        return accessToken
    }
}

async function verifyToken(token) {
    try {
        if (!token) return false

        let split = token.split('.')
        if (split.length == 3) {
            if (split[1] !== SIGNATURE) return false
            let timestamp = parseInt(split[2], 10)
            let now = Date.now()
            let diff = now - timestamp

            if (diff > 120000 || diff < -60000) return false
            return true
        }
    } catch (error) {}

    return false
}

function getBody(res) {
    return new Promise((resolve) => {
        let buffer = ''

        res.onData((chunk, isLast) => {
            buffer += Buffer.from(chunk).toString()
            if (isLast) {
                try {
                    let json = JSON.parse(buffer)
                    resolve(json)
                } catch {
                    resolve({})
                }
            }
        })

        res.onAborted(() => resolve({}))
    })
}

function getHeaders() {
    return {
        'Content-Type': 'application/json',
        'X-Android-Package': PACKAGE,
        'X-Android-Cert': CERT,
        'Accept-Language': 'en-GB, en-US',
        'X-Client-Version': VERSION,
        'X-Firebase-Gmpid': GMP_ID,
        'X-Firebase-Client': CLIENT,
        'User-Agent': 'Dalvik/2.1.0',
        'Accept-Encoding': 'gzip, deflate'
    }
}

function encrypt(text) {
    try {
        let cipher = crypto.createCipheriv('aes-192-cbc', KEY, IV)
        return cipher.update(text, 'utf8', 'base64') + cipher.final('base64')
    } catch (e) {
        return ''
    }
}

function decrypt(text) {
    try {
        let cipher = crypto.createDecipheriv('aes-192-cbc', KEY, IV)
        return cipher.update(text, 'base64', 'utf8') + cipher.final('utf8')
    } catch (e) {
        return null
    }
}