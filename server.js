require('dotenv').config()

const crypto = require('crypto')
const express = require('express');
const accountSid = process.env.ACCOUNT_SID
const authToken = process.env.AUTH_TOKEN
const cors = require('cors');
let refreshTokens = []
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const client = require('twilio')(accountSid, authToken)

const jwtAuthToken = process.env.JWT_AUTH_TOKEN

const jwtRefreshToken = process.env.JWT_REFRESH_TOKEN
const smsSecretKey = process.env.SMS_SECRET_KEY

const app = express();
app.use(express.json())
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(cookieParser())


app.post('/sendOTP', (req, res) => {
    console.log('hii')
    const phnno = req.body.phone;
    const otp = Math.floor(100000 + Math.random() * 900000);
    const ttl = 180 * 60 * 1000;
    const expireTime = Date.now() + ttl;
    const data = `${phnno}.${otp}.${expireTime}`
    const hash = crypto.createHmac('sha256', smsSecretKey).update(data).digest('hex')
    const fullHash = `${hash}.${expireTime}`;
    client.messages.create({
        body: `Your Otp is: ${otp}`,
        from: `+14157893861`,
        to: phnno
    }).then((message) => console.log(message)).catch((err) => console.error(err))

    res.status(200).send({ phnno, hash: fullHash, otp })

});

app.post('/verifyOTP', (req, res) => {
    const phone = req.body.phone;
    const otp = req.body.otp;
    let [hash, expireTime] = req.body.hash.split('.');
    let now = Date.now();
    if (now > parseInt(expireTime)) {
        return res.status(504).send({ msg: 'TimeOut' })
    }
    const data = `${phone}.${otp}.${expireTime}`;
    const checkHash = crypto.createHmac('sha256', smsSecretKey).update(data).digest('hex');
    if (hash === checkHash) {
        
        const accessToken = jwt.sign({ data: phone }, jwtAuthToken, { expiresIn: '30s' })
        const refreshToken = jwt.sign({ data: phone }, jwtRefreshToken, { expiresIn: '30s' })
        refreshTokens.push(refreshToken);
        res.status(202).cookie('accessToken', accessToken, { expires: new Date(new Date().getTime + 30 * 1000), sameSite: 'strict', httpOnly: true, },)
            .cookie('authSession', true, { expires: new Date(new Date().getTime + 5 * 60 * 1000), },)
            .cookie('refreshToken', refreshToken, { expires: new Date(new Date().getTime + 5 * 60 * 1000), sameSite: 'strict', httpOnly: true },)
            .cookie('refreshTokenId', true, { expires: new Date(new Date().getTime + 5 * 60 * 1000), },)
            .send({ msg: 'Device Verified' })
    }
    else {
        return res.send(400).send({ msg: 'Invalid Credential' })
    }
})

async function authenticateUser(req, res, next) {
    const accessToken = req.cookies.accessToken

    jwt.verify(accessToken, jwtAuthToken, async (err, phone) => {
        if (phone) {
            req, phone = phone;
            next()
        } else if (err.message === 'TokenExpiredError') {
            return res.status(403).send({ success: false, msg: 'Token Expired' })
        }
        else {
            console.error(err)
            res.status(403).send({ err, msg: 'User Not Authenticated' })
        }
    })
}
app.post('/refresh', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(403).send({ msg: `refresh Token not found,Please login again` })
    if (!refreshTokens.includes(refreshToken)) return res.status(403).send({ msg: `Refresh token blocked,login again` })
    jwt.verify(refreshToken, jwtRefreshToken, (err, phone) => {
        if (!err) {
            const accessToken = jwt.sign({ data: phone }, jwtAuthToken, { expiresIn: '30s' });
            res.status(202).cookie('accessToken', accessToken, { expires: new Date(new Date().getTime + 30 * 1000), sameSite: 'strict', httpOnly: true, },)
                .cookie('authSession', true, { expires: new Date(new Date().getTime + 5 * 60 * 1000), },).send({ previousSessionExpires: true, success: true })
        } else {
            res.status(403).send({ success: true, msg: 'Invalid Refresh token' })
        }
    })
})

app.get('/logout', (req, res) => {
    res.clearCookie('refreshToken').clearCookie('accessToken').clearCookie('authSession').clearCookie('refreshTokenId').send('User Logout');
})
app.listen(process.env.PORT||4000)
