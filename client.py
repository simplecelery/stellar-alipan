import os
import requests
import time
import threading
import base64
import json

from urllib import parse
from config import *


class Client:
    def __init__(self, tokenChanged):
        self.session = requests.session()
        self.session.params.update(UNI_PARAMS)  # type:ignore
        self.session.headers.update(UNI_HEADERS)

        self.session.get(AUTH_HOST + V2_OAUTH_AUTHORIZE, params={
            'login_type': 'custom',
            'response_type': 'code',
            'redirect_uri': 'https://www.aliyundrive.com/sign/callback',
            'client_id': CLIENT_ID,
            'state': r'{"origin":"file://"}',
            # 'state': '{"origin":"https://www.aliyundrive.com"}',
        }, stream=True).close()

        SESSIONID = self.session.cookies.get('SESSIONID')
        print(f'SESSIONID {SESSIONID}')

        try:
            f = open("token.json", "r")
            self.token = json.loads(f.read())
            f.close()
        except:
            self.token = None

        self.tokenChanged = tokenChanged

    def login(self):
        response = self.session.get(
            PASSPORT_HOST + NEWLOGIN_QRCODE_GENERATE_DO
        )
        data = response.json()['content']['data']
        print('等待扫描二维码 ...')
        print('扫描成功后，请手动关闭图像窗口 ...')

        t = threading.Thread(target=self.checkLogin, args=(data,))
        t.start()

        return data['codeContent']

    def logout(self):
        try:
            os.remove("token.json")
        except:
            raise
            pass
        self.token = None
        self.tokenChanged()

    def checkLogin(self, data):
        while True:
            response = self.session.post(
                PASSPORT_HOST + NEWLOGIN_QRCODE_QUERY_DO,
                data=data
            )
            login_data = response.json()['content']['data']
            qrCodeStatus = login_data['qrCodeStatus']
            # self.log.info('等待扫描二维码 ...')
            if qrCodeStatus == 'NEW':
                # self.log.info('等待扫描二维码 ...')
                pass
            elif qrCodeStatus == 'SCANED':
                print('已扫描, 等待确认 ...')
            elif qrCodeStatus == 'CONFIRMED':
                print(f'已确认 (你可以关闭二维码图像了).')
                return self.onLoginResponse(response)
            else:
                print('未知错误: 可能二维码已经过期.')
                raise Exception("error")
            time.sleep(2)

    def onLoginResponse(self, response):
        if response.status_code != 200:
            return self.tokenChanged('登录失败 ~')
        
        bizExt = response.json()['content']['data']['bizExt']
        bizExt = base64.b64decode(bizExt).decode('gb18030')
        accessToken = json.loads(bizExt)['pds_login_result']['accessToken']

        # 使用accessToken持久化身份认证
        response = self.session.post(
            AUTH_HOST + V2_OAUTH_TOKEN_LOGIN,
            json={
                'token': accessToken
            }
        )

        goto = response.json()['goto']
        code: str = parse.parse_qs(parse.urlparse(goto).query)['code'][0]  # type: ignore

        response = self.session.post(
            WEBSV_HOST + TOKEN_GET,
            json={
                'code': code
            }
        )

        if response.status_code != 200:
            return self.tokenChanged('登陆失败 ~')

        self.token = response.json()

        #
        print(f'username: {self.token["user_name"]} nickname: {self.token["nick_name"]} user_id: {self.token["user_id"]}')

        # 保存
        self._save()

        self.tokenChanged()

    def _save(self):
        if self.token:
            f = open("token.json", "w+")
            f.write(json.dumps(self.token, indent=2))
            f.close()

    def _refesh_token(self, refresh_token=None):
        """刷新 token"""
        if refresh_token is None:
            refresh_token = self.token["refresh_token"]
        print('刷新 token ...')
        response = self.session.post(
            API_HOST + TOKEN_REFRESH,
            json={'refresh_token': refresh_token}
        )
        if response.status_code == 200:
            self.token = response.json()
            self._save()
        else:
            print('刷新 token 失败 ~')
            self.token = None

        print(f'刷新 token {self.token["access_token"]}')
        self.session.headers.update({
            'Authorization': f'Bearer {self.token["access_token"]}'
        })

        self.tokenChanged()
        # error_log_exit(response)

    def request(self, method: str, url: str,
                params, headers, data,
                files, verify, body) :
        """统一请求方法"""        
        if 'drive_id' in body and body['drive_id'] is None:
            body['drive_id'] = self.token['default_drive_id']

        # 删除值为None的键
        if body is not None:
            body = {k: v for k, v in body.items() if v is not None}

        if data is not None and isinstance(data, dict):
            data = {k: v for k, v in data.items() if v is not None}

        for i in range(3):
            print(
                f'{method} {url} {params} {data} {headers} {files} {verify} {body}'
            )
            response = self.session.request(method=method, url=url, params=params,
                                            data=data, headers=headers, files=files,
                                            verify=verify, json=body)
            status_code = response.status_code
            print(
                f'{i} {response.request.method} {response.url} {status_code} {response.headers.get("Content-Length", 0)}'
            )
            if status_code == 401 or (
                    # aims search 手机端apis
                    status_code == 400 and response.text.startswith('AccessToken is invalid')
            ):
                self._refesh_token()
                continue

            if status_code == 429 or status_code == 500:
                print('被限流了, 休息一下 ...')
                time.sleep(5)
                continue

            return response

        print(f'重试3次仍旧失败~')
        return response

    def get(self, path, host = API_HOST, params = None, headers = None,
            verify = None) :
        return self.request(method='GET', url=host + path, params=params,
                            headers=headers, verify=verify)

    def post(self, path, host = API_HOST, params = None, headers = None, data = None,
             files=None, verify = None, body = None):
        return self.request(method='POST', url=host + path, params=params, data=data,
                            headers=headers, files=files, verify=verify, body=body)

    def get_file_list(self, parent_file_id='root', drive_id=None):
        print(f'get_file_list: {parent_file_id}')
        body = dict(
            parent_file_id=parent_file_id,
            drive_id=drive_id,
            starred=None,
            all=False,
            category=None,
            fields='*',
            image_thumbnail_process='image/resize,w_400/format,jpeg',
            image_url_process='image/resize,w_400/format,jpeg',
            limit=200,
            marker=None,
            order_by='updated_at',
            order_direction='DESC',
            status=None,
            type=None,
            url_expire_sec=14400,
            video_thumbnail_process='video/snapshot,t_0,f_jpg,ar_auto,w_800'
        )   
        response = self.post(ADRIVE_V3_FILE_LIST, body=body)
        if response.status_code == 200:
            for item in response.json()["items"]:
                print(item)
                if item["type"] == "folder":
                    url = ""
                elif item["category"] == "video":
                    url = item["download_url"] 
                else:
                    continue
                yield dict(
                    name=item["name"],
                    type=item["type"],
                    file_id=item["file_id"],
                    url = url
                )
        return None

def tokenChanged(msg=None):
    print(f'tokenChanged: {msg}')

def main():
    c = Client(tokenChanged)
    if c.token is None:
        print(c.login())
    print('----------')
    while 1:
        if c.token is not None:
            break
        time.sleep(1.0)
    files = c.get_file_list()
    for file in files:
        if file["type"] == 'folder':
            print(f'[{file["name"]}]')
        elif file["type"] == 'file':
            print(f'{file["name"]} - {file["url"]}')
                

if __name__ == "__main__":
    main()
