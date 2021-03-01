import http from 'http'
import crypto from 'crypto'
import querystring from 'querystring'
import axios from 'axios'

const getRequestTokenUrl = 'https://api.twitter.com/oauth/request_token';
const getAccessTokenUrl = 'https://api.twitter.com/oauth/access_token';
const callbackUrl = 'https://wind-chime.herokuapp.com/';
const consumerKey = '';
const consumerSecret = '';
const keyOfSign = encodeURIComponent(consumerSecret) + '&';

class RequestTokenMethods {
  constructor() {
    this.dataOAuth = {
      oauthToken: '',
      oauthTokenSecret: '',
      oauthVerifier: '',
      // oauthVerifierとユーザ名のハッシュ化した値の保持などに利用
      oauthHashKey: '',
    };
  }
 dataOAuth = {
    oauthToken: '',
    oauthTokenSecret: '',
    oauthVerifier: '',
    // oauthVerifierとユーザ名のハッシュ化した値の保持などに利用
    oauthHashKey: '',
  };

  getOAuthData() {
    return this.dataOAuth;
  }

  setOAuthData(props: string | undefined, reqProps = 'oauthToken') {
    if (!props) return
    switch (reqProps) {
      case 'oauthToken':
        this.dataOAuth.oauthToken = props;
      case 'oauthTokenSecret':
        this.dataOAuth.oauthTokenSecret = props;
      case 'oauthVerifier':
        this.dataOAuth.oauthVerifier = props;
      case 'oauthHashKey':
        this.dataOAuth.oauthHashKey = props;
      default:
        return;
    }
  }

  async getRequestToken(params: PramsRequestToken) {
    Object.keys(params).forEach((item) => {
      params[item] = encodeURIComponent(params[item]);
    });

    const requestParams = encodeURIComponent(
      Object.keys(params).map(item => {
        return item + '=' + params[item];
      }).sort((a, b) => {
        if (a < b) return -1;
        if (a > b) return 1;
        return 0;
      }).join('&')
    );

    const dataOfSign = (() => {
      return encodeURIComponent('POST') + '&' + encodeURIComponent(getRequestTokenUrl) + '&' + requestParams;
    })();

    const signature = (() => {
      return crypto.createHmac('sha1', keyOfSign).update(dataOfSign).digest('base64');
    })();

    params['oauth_signature'] = encodeURIComponent(signature);

    const headerParams = Object.keys(params).map(item => {
      return item + '=' + params[item];
    }).join(',');

    const header = {
      'Authorization': 'OAuth ' + headerParams
    };

    //オプションを定義
    const options = {
      url: getRequestTokenUrl,
      headers: header,
    };
    //リクエスト送信
    return await this.getTokenSync(options)
  }
  async getAccessToken(params: ParamsAccessToken) {
    Object.keys(params).forEach(item => {
      params[item] = encodeURIComponent(params[item]);
    });

    const requestParams = encodeURIComponent(
      Object.keys(params).map(item => {
        return item + '=' + params[item];
      }).sort((a, b) => {
        if (a < b) return -1;
        if (a > b) return 1;
        return 0;
      }).join('&')
    )

    const dataOfSign = (() => {
      return encodeURIComponent('POST') + '&' + encodeURIComponent(getAccessTokenUrl) + '&' + requestParams;
    })();

    const signature = (() => {
      return crypto.createHmac('sha1', keyOfSign).update(dataOfSign).digest('base64');
    })();

    params['oauth_signature'] = encodeURIComponent(signature);

    const headerParams = Object.keys(params).map(item => {
      return item + '=' + params[item];
    }).join(',');

    const header = {
      'Authorization': 'OAuth ' + headerParams
    };

    //オプションを定義
    const options = {
      url: getAccessTokenUrl,
      headers: header,
    };
    //リクエスト送信
    return await this.getTokenSync(options)
  }

  private async getTokenSync(options: { url: string, headers: { Authorization: string } }){
    const res = await axios.post(options.url, options.headers)
    if (res) {
      const tmpData = {
        oauth_token: querystring.parse(res.data).oauth_token,
        oauth_token_secret: querystring.parse(res.data).oauth_token_secret,
      }
      return tmpData;
    } else {
      console.error(res)
    }
  }
}
type PramsRequestToken = Record<string, string | number> & {
  oauth_callback: typeof callbackUrl
  oauth_consumer_key: typeof consumerKey
  oauth_signature_method: string
  oauth_timestamp: number
  oauth_nonce: number
  oauth_version: string
}

const getPramsRequestToken = (): PramsRequestToken => ({
  oauth_callback: callbackUrl,
  oauth_consumer_key: consumerKey,
  oauth_signature_method: 'HMAC-SHA1',
  oauth_timestamp: (() => {
    const date = new Date();
    return Math.floor(date.getTime() / 1000);
  })(),
  oauth_nonce: (() => {
    const date = new Date();
    return date.getTime();
  })(),
  oauth_version: '1.0',
});

type ParamsAccessToken = Record<string, string | number> & {
  consumer_key: typeof consumerKey,
  oauth_token: string
  oauth_signature_method: string
  oauth_timestamp: number
  oauth_verifier: string
  oauth_nonce: number
  oauth_version: string
}

const getParamsAccessToken = (requestMethod: RequestTokenMethods): ParamsAccessToken => {
  return {
    consumer_key: consumerKey,
    oauth_token: requestMethod.dataOAuth.oauthToken,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: (() => {
      const date = new Date();
      return Math.floor(date.getTime() / 1000);
    })(),
    oauth_verifier: requestMethod.dataOAuth.oauthVerifier,
    oauth_nonce: (() => {
      const date = new Date();
      return date.getTime();
    })(),
    oauth_version: '1.0'
  }
}

http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://api.twitter.com/*');
  res.setHeader('Access-Control-Allow-Origin', '<Client URL>');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');

  if (req.method === 'POST') {
    req.on('data', async (data: unknown) => {
      const resData = data + '';
      const paramsRequestToken = getPramsRequestToken()
      const requestMethod = new RequestTokenMethods();
      if (resData === 'request_token' && requestMethod.getOAuthData().oauthVerifier !== '') {
        const tokenOAuth = await requestMethod.getRequestToken(paramsRequestToken)
        if (tokenOAuth) {
          if (tokenOAuth.oauth_token && !Array.isArray(tokenOAuth.oauth_token)) {
            const oauthUri = 'https://api.twitter.com/oauth/authorize?oauth_token=' + encodeURIComponent(tokenOAuth.oauth_token)
            req.on('end', () => {
              res.writeHead(200, {
                'Content-Type': 'application/json'
              });
              res.write(oauthUri);
              res.end();
            });
          }
        } else {
          console.log(tokenOAuth);
          res.writeHead(408, {
            'Content-Type': 'application/json'
          });
          res.write('error!');
          res.end();
        }
      }
    })
  } else if (req.method === 'GET') {
    const reqURI = req.url;
    if (reqURI && reqURI.match(/oauth_verifier/)) {
      const getQueryVariable = (variable: string) => {
        const query = reqURI.substring(1);
        const varbs = query.split('&');
        let pair: string[] = []
        varbs.forEach((varb) => {
          pair = varb.split('=');
        })
        if (pair[0] === variable) {
          return pair[1];
        }
      }
      const requestMethod = new RequestTokenMethods();
      const dataOAuthToken = requestMethod.getOAuthData();
      requestMethod.setOAuthData(getQueryVariable('oauth_verifier'), 'oauthVerifier');
      requestMethod.setOAuthData(getQueryVariable('oauth_token'), 'oauthToken');
      const paramsAccessToken = getParamsAccessToken(requestMethod)
      const tokenOAuth = await requestMethod.getAccessToken(paramsAccessToken)
      if (tokenOAuth && tokenOAuth.oauth_token && tokenOAuth.oauth_token_secret) {
        if (!Array.isArray(tokenOAuth.oauth_token) && !Array.isArray(tokenOAuth.oauth_token_secret)) {
          requestMethod.setOAuthData(tokenOAuth.oauth_token, 'oauthToken');
          requestMethod.setOAuthData(tokenOAuth.oauth_token_secret, 'oauthTokenSecret');
          const keyOfToken = crypto.createHmac('sha256', dataOAuthToken.oauthVerifier + dataOAuthToken.oauthToken);
          requestMethod.setOAuthData(keyOfToken.digest('base64'), 'oauthHashKey');
          const tmpDate = new Date()
          tmpDate.setDate(tmpDate.getDate() + 3)
          res.setHeader('Set-Cookie', [
            `id=${dataOAuthToken.oauthHashKey}; path=${'<Client URL>'}; expires=${tmpDate}`
          ])
          res.writeHead(302, {
            'Location': '<Client URL>',
          });
          res.write('redirect!');
        }
      }
      res.end();
    } else {
      res.writeHead(408, {
        'Content-Type': 'application/json'
      });
      res.write('error!');
      res.end();
    }
  }
}).listen(process.env.PORT ? process.env.PORT : 8080);
