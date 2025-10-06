require('dotenv').config()
const axios = require('axios')
const crypto = require('crypto')
const express = require('express')
const bodyParser = require('body-parser')

const app = express()
app.use(bodyParser.json())

const DATABASE = process.env.DATABASE
const SIGNATURE = process.env.SIGNATURE
const API_KEY = process.env.API_KEY
const CERT = process.env.CERT
const GMP_ID = process.env.GMP_ID
const CLIENT = process.env.CLIENT
const PORT = process.env.PORT || 3000
const VERSION = 'Android/Fallback/X24000001/FirebaseCore-Android'
const PACKAGE = 'com.rr.bubtbustracker'

let KEY = Buffer.from(process.env.AES_KEY.split(',').map(n => parseInt(n.trim())))
let IV = Buffer.from(process.env.AES_IV.split(',').map(n => parseInt(n.trim())))

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

app.post('/login', async (req, res) => {
    let { email, password, token } = req.body

    if (!email || !password || !token) {
        return res.json({ status: 'FIELD_EMPTY' })
    }

    if (!email.includes('@') || email.indexOf('@') > email.lastIndexOf('.')) {
        return res.json({ status: 'WRONG_EMAIL' })
    }

    password = decrypt(password)

    if (!password) {
        return res.json({ status: 'ERROR' })
    }

    if (password.length < 6) {
        return res.json({ status: 'PASSWORD_LENGTH_SHORT' })
    }

    let validToken = await verifyToken(decrypt(token))

    if (!validToken) {
        return res.json({ status: 'ERROR' })
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
                    
                    response = await axios.get(DATABASE+'user/'+localId+'.json')
                    let data = response.data
                    if (data) {
                        return res.json({
                            status: 'SUCCESS', 
                            rule: data.rule,
                            name: data.name,
                            bus: data.bus,
                            id: localId,
                            verified: emailVerified,
                            passwordUpdatedAt: users[0].passwordUpdatedAt, 
                            lastLoginAt: users[0].lastLoginAt,
                            createdAt: users[0].createdAt,
                            refreshToken: refreshToken,
                            accessToken: idToken,
                            requestToken: encrypt(API_KEY+'|'+CERT+'|'+GMP_ID+'|'+CLIENT)
                        })
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
    return res.json({ status: result })
})


app.post('/reset', async (req, res) => {
    let { email, token } = req.body

    if (!email || !token) {
        return res.json({ status: 'FIELD_EMPTY' })
    }

    if (!email.includes('@') || email.indexOf('@') > email.lastIndexOf('.')) {
        return res.json({ status: 'WRONG_EMAIL' })
    }

    let validToken = await verifyToken(decrypt(token))

    if (!validToken) {
        return res.json({ status: 'ERROR' })
    }

    try {
        await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key='+API_KEY, { 'requestType': 1, 'email': email, androidInstallApp: false, canHandleCodeInApp: false, 'clientType': 'CLIENT_TYPE_ANDROID' }, { headers: getHeaders() })
        return res.json({ status: 'SUCCESS' })
    } catch (error) {
        return res.json({ status: 'ERROR' })
    }
})


app.post('/verification', async (req, res) => {
    let authHeader = req.headers['authorization'] || req.headers['Authorization'];
    let { accessToken, token } = req.body

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.json({ status: 'NO_HEADER_TOKEN' })
    }

    let refreshToken = authHeader.split(' ')[1]

    if (!token) {
        return res.json({ status: 'ERROR' })
    }
    
    let validToken = await verifyToken(decrypt(token))

    if (!validToken) {
        return res.json({ status: 'ERROR' })
    }

    if (!accessToken) {
        accessToken = await getAccessToken(refreshToken, null)
    }

    if (!accessToken) {
        return res.json({ status: 'NO_ACCESS_TOKEN' })
    }

    let result = 'ERROR'
    let letestToken = null

    for (let i = 0; i < 2; i++) {
        try {
            let response = await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key='+API_KEY, { 'idToken': accessToken }, { headers: getHeaders() })

            if (response.data.kind.includes('GetAccountInfoResponse')) {
                let users = response.data.users
                let emailVerified = users[0].emailVerified
                let localId = users[0].localId
                
                try {
                    if (Math.floor((Date.now() - new Date(users[0].lastRefreshAt).getTime()) / (1000 * 60)) > 45) {
                        letestToken = await getAccessToken(refreshToken, accessToken)
                        accessToken = letestToken
                    }
                } catch (error) {}

                try {
                    await axios.post('https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key='+API_KEY, { 'requestType': 4, 'idToken': accessToken, 'clientType': 'CLIENT_TYPE_ANDROID' }, { headers: getHeaders() })
                } catch (error) {}
                

                return res.json({
                    status: 'SUCCESS',
                    id: localId,
                    verified:emailVerified,
                    passwordUpdatedAt: users[0].passwordUpdatedAt, 
                    lastLoginAt: users[0].lastLoginAt,
                    createdAt: users[0].createdAt,
                    letestToken: letestToken
                })
            }
        } catch (error) {
            result = 'ERROR'
            try {
                if (error.response && error.response.data) {
                    let msg = error.response.data.error.message
                    if (msg == 'INVALID_ID_TOKEN' || msg == 'TOKEN_EXPIRED') {
                        letestToken = await getAccessToken(token, accessToken)
                        accessToken = letestToken
                        continue
                    }
                }
            } catch (error) {}
        }

        break
    }

    return res.json({ status: result })
})


app.post('/sign_up', async (req, res) => {
    let { email, password, name, bus, token } = req.body

    if (!email || !password || !name || !bus || !token) {
        return res.json({ status: 'FIELD_EMPTY' })
    }

    if (!email.includes('@') || email.lastIndexOf('@') > email.lastIndexOf('.')) {
        return res.json({ status: 'WRONG_EMAIL' })
    }

    password = decrypt(password)

    if (!password) {
        return res.json({ status: 'ERROR' })
    }

    if (password.length < 6) {
        return res.json({ status: 'PASSWORD_LENGTH_SHORT' })
    }

    let validToken = await verifyToken(decrypt(token))

    if (!validToken) {
        return res.json({ status: 'ERROR' })
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

            await axios.patch(DATABASE+'user/'+localId+'.json', { token: refreshToken, rule: 'STUDENT', name, bus }, {
                headers: {
                    'Content-Type': 'application/json' 
                }
            })

            return res.json({
                status: 'SUCCESS',
                id: localId,
                refreshToken: refreshToken,
                accessToken: idToken,
                requestToken: encrypt(API_KEY+'|'+CERT+'|'+GMP_ID+'|'+CLIENT)
            })
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
    return res.json({ status: result })
})


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
            if (diff > 2 * 60 * 1000 || diff < 0) return false
            return true
        }
    } catch (error) {}

    return false
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


app.listen(PORT, () => console.log(`Server running PORT: ${PORT}`))
