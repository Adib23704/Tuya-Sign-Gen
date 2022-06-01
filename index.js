const qs = require("qs");
const crypto = require("crypto");
const axios = require("axios");
const express = require('express');
const router = express.Router();
const app = express();

app.disable("etag");
app.disable("x-powered-by");
router.get('/getsign', async (req, res) => {
    if (!req.get('accesskey')) {
        return res.status(404).json({ error: true, msg: 'No accessKey provided!' });
    }
    if (!req.get('secretkey')) {
        return res.status(404).json({ error: true, msg: 'No secretKey provided!' });
    }
    if (!req.get('method')) {
        return res.status(404).json({ error: true, msg: 'No method provided!' });
    }
    if (!req.get('url')) {
        return res.status(404).json({ error: true, msg: 'No url provided!' });
    }
    const accesskey = req.get('accesskey');
    const secretkey = req.get('secretkey');
    const method = req.get('method');
    const url = req.get('url');


    const nonce = '';
    const methodTemp = 'GET';
    const timestamp = Date.now().toString();
    const signUrl = '/v1.0/token?grant_type=1';
    const contentHash = crypto.createHash('sha256').update('').digest('hex');
    const signHeaders = Object.keys({});
    const signHeaderStr = Object.keys(signHeaders).reduce((pre, cur, idx) => {
        return `${pre}${cur}:${{}[cur]}${idx === signHeaders.length - 1 ? '' : '\n'}`;
    }, '');
    const stringToSign = [methodTemp, contentHash, signHeaderStr, signUrl].join('\n');
    const signStr = accesskey + timestamp + nonce + stringToSign;
    const sign = await encryptStr(signStr, secretkey);
    const headers = {
        t: timestamp,
        sign_method: 'HMAC-SHA256',
        client_id: accesskey,
        sign: sign
    };

    const options = {
        headers: headers,
    };
    const { data: login } = await httpClient.get('/v1.0/token?grant_type=1', options);
    if (!login || !login.success) {
        return console.log("Token Error: ", login);
    }

    token = login.result.access_token;

    let reqHeaders = await getRequestSign(accesskey, secretkey, url, method, (req.get('query')) ? (req.get('query')) : ({}), (req.get('body')) ? (req.get('body')) : ({}));

    reqHeaders = { accesskey, ...reqHeaders };
    reqHeaders = { secretkey, ...reqHeaders };

    res.status(200).json(reqHeaders);
});

app.use('/', router);
app.listen(80);

let token = '';

const httpClient = axios.create({
    baseURL: 'https://openapi.tuyaeu.com',
    timeout: 5 * 1e3,
});

async function encryptStr(str, secret) {
    return crypto.createHmac('sha256', secret).update(str, 'utf8').digest('hex').toUpperCase();
}

async function getRequestSign(accesskey, secretkey, path, method, query = {}, body = {}) {
    const t = Date.now().toString();
    const [uri, pathQuery] = path.split('?');
    const queryMerged = Object.assign(query, qs.parse(pathQuery));
    const sortedQuery = {};
    Object.keys(queryMerged).sort().forEach(i => sortedQuery[i] = query[i]);
    const querystring = qs.stringify(sortedQuery);
    const url = querystring ? `${uri}?${querystring}` : uri;
    const contentHash = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
    // const stringToSign = [method, contentHash, '', decodeURIComponent(url)].join('\n');
    const stringToSign = [method, contentHash, '', path].join('\n');
    const signStr = accesskey + token + t + stringToSign;
    return {
        t,
        access_token: token,
        signMain: await encryptStr(signStr, secretkey),
        sign_method: 'HMAC-SHA256'
    };
}