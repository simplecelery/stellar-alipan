import os
import requests
import time
import threading
import base64
import json
import uuid

from urllib import parse
from config import *


class Client:
    def __init__(self, tokenChanged):
        self.session = requests.session()
        self.session.trust_env = False
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

        self._x_device_id = None
        self.tokenChanged = tokenChanged
        self._SLEEP_TIME_SEC = None
        self._X_SIGNATURE = ('f4b7bed5d8524a04051bd2da876dd79afe922b8205226d65855d02b267422adb1'
                             'e0d8a816b021eaf5c36d101892180f79df655c5712b348c2a540ca136e6b22001')

        try:
            f = open("token.json", "r")
            self.token = json.loads(f.read())            
            f.close()
            self._init_x_headers()
        except:
            raise
            self.token = None



    def _init_x_headers(self):
        if self._x_device_id is None:
            # 如果 self._x_device_id 为 None，尝试从 token 中获取（来自文件）
            self._x_device_id = self.token.get('x_device_id')
        if self._x_device_id is None:
            # 如果文件中未存储，则说明还没有，则生成
            self._x_device_id = uuid.uuid4().hex
        # 设置 x-headers
        self.session.headers.update({
            'x-device-id': self._x_device_id,
            'x-signature': self._X_SIGNATURE
        })
        # 将 x-headers 放到 token 对象中，用以保存
        if not self.token.get('x_device_id'):
            print('初始化 x_device_id')
            self.token['x_device_id'] = self._x_device_id
            self._save()

    def login(self):
        response = self.session.get(
            PASSPORT_HOST + NEWLOGIN_QRCODE_GENERATE_DO, params=UNI_PARAMS
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
                data=data, params=UNI_PARAMS
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
        # print(response)
        if response.status_code != 200:
            return self.tokenChanged('登录失败 ~')
        
        bizExt = response.json()['content']['data']['bizExt']
        bizExt = base64.b64decode(bizExt).decode('gb18030')

       # 获取解析出来的 refreshToken, 使用这个token获取下载链接是直链, 不需要带 referer header
        refresh_token = json.loads(bizExt)['pds_login_result']['refreshToken']

        self._refesh_token(refresh_token)        

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
            API_HOST + V2_ACCOUNT_TOKEN,
            json={
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }
        )
        if response.status_code == 200:
            self.token = response.json()
            if not self._x_device_id:
                self._init_x_headers()
            self._save()
        else:
            print('刷新 token 失败 ~')
            self.token = None

        print(f'刷新 token {self.token["access_token"]}')
        self.session.headers.update({
            'Authorization': f'{self.token["access_token"]}'
        })

        self.tokenChanged()

    def request(self, method: str, url: str,
                params, headers, data,
                files, verify, body) :
        """统一请求方法"""
        # 删除值为None的键
        if body is not None:
            body = {k: v for k, v in body.items() if v is not None}

        if data is not None and isinstance(data, dict):
            data = {k: v for k, v in data.items() if v is not None}

        response = None
        for i in range(1, 6):
            try:
                print(f'{url=} {params=} {data=} {headers=} {body=}')
                response = self.session.request(
                    method=method, url=url, params=params, data=data,
                    headers=headers, verify=True, json=body, timeout=10.0
                )
            except requests.exceptions.ConnectionError as e:
                print(e)
                time.sleep(self._request_failed_delay)
                continue

            status_code = response.status_code
            print(response)

            if status_code == 401:
                if b'"ShareLinkTokenInvalid"' in response.content:
                    # 刷新 share_token
                    share_id = body['share_id']
                    share_pwd = body['share_pwd']
                    r = self.post(
                        V2_SHARE_LINK_GET_SHARE_TOKEN,
                        body={'share_id': share_id, 'share_pwd': share_pwd}
                    )
                    share_token = r.json()['share_token']
                    headers['x-share-token'].share_token = share_token
                elif b'"UserDeviceOffline"' in response.content:
                    self._create_session()
                else:
                    self._refesh_token()
                continue

            if status_code in [429, 502, 504]:
                if self._SLEEP_TIME_SEC is None:
                    sleep_int = 5 ** (i % 4)
                else:
                    sleep_int = self._SLEEP_TIME_SEC
                err_msg = None
                if status_code == 429:
                    err_msg = '请求太频繁'
                elif status_code == 502:
                    err_msg = '内部网关错误'
                elif status_code == 504:
                    err_msg = '内部网关超时'
                print(f'{err_msg}，暂停 {sleep_int} 秒钟')
                time.sleep(sleep_int)
                continue

            if status_code == 500:
                raise Exception(response.content)

            if status_code == 400:
                if b'"DeviceSessionSignatureInvalid"' in response.content \
                        or b'"not found device info"' in response.content:
                    self._create_session()
                    continue
                elif b'"InvalidResource.FileTypeFolder"' in response.content:
                    print(
                        '请区分 文件 和 文件夹，有些操作是它们独有的，比如获取下载链接，很显然 文件夹 是没有的！')

            if status_code == 403:
                if b'"SharelinkCreateExceedDailyLimit"' in response.content:
                    raise Exception(response.content)

            return response

        print(f'重试 5 次仍失败，抛出异常')
        raise Exception(response.content)

    def _create_session(self):
        self.post(USERS_V1_USERS_DEVICE_CREATE_SESSION,
                  body={'deviceName': f'my cp', 'modelName': 'Windows 操作系统', 'pubKey':  ('04d9d2319e0480c840efeeb75751b86d0db0c5b9e72c6260a1d846958adceaf9d'
                     'ee789cab7472741d23aafc1a9c591f72e7ee77578656e6c8588098dea1488ac2a'), })

    def get(self, path, host = API_HOST, params = None, headers = None,
            verify = None) :
        return self.request(method='GET', url=host + path, params=params,
                            headers=headers, verify=verify)

    def post(self, path, host = API_HOST, params = None, headers = None, data = None,
             files=None, verify = None, body = None):
        if 'drive_id' in body and body['drive_id'] is None:
            # 如果存在 attr drive_id 并且它是 None，并将 default_drive_id 设置为它
            body['drive_id'] = self.token.get('default_drive_id')
        print(f'{host + path=} {params=} {data=} {headers=} {body=}')
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
                # print(item)
                for k, v in item.items():
                    print(k + "=" + str(v))
                if item["type"] == "folder":
                    url = ""
                elif item["category"] == "video":
                    # url = item["download_url"] 
                    url = item["url"] 
                else:
                    continue
                yield dict(
                    name=item["name"],
                    type=item["type"],
                    file_id=item["file_id"],
                    drive_id=item["drive_id"],
                    url = url
                )
        return None

    def get_video_preview_play_info(self, file_id='root', drive_id=None):
        print(f'get_video_preview_info: {file_id}')
        body = dict(
            file_id=file_id,
            drive_id=drive_id,
            template_id='',
            url_expire_sec=14400,
            category='live_transcoding'
        )
        response = self.post(V2_FILE_GET_VIDEO_PREVIEW_PLAY_INFO, body=body)
        if response.status_code == 200:
            try:
                return response.json()["video_preview_play_info"]["live_transcoding_task_list"][-1]["url"]
            except:
                pass
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
    # files = c.get_file_list()
    # for file in files:
    #     if file["type"] == 'folder':
    #         # print(f'[{file["name"]}]')
    #         pass
    #     elif file["type"] == 'file':
    #         print(f'{file["name"]} - {file["url"]} ---- {file=}')
    ret = c.get_video_preview_play_info('64e5b5aa624c5ccd6e6d4b6cbb756f94bf816a24')
    print(ret)
                

if __name__ == "__main__":
    main()
