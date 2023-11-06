import StellarPlayer
import json
import os
import sys

sys.path.append(os.path.dirname(__file__))

from .client import Client

class myplugin(StellarPlayer.IStellarPlayerPlugin):
    def __init__(self,player:StellarPlayer.IStellarPlayer):
        StellarPlayer.IStellarPlayerPlugin.__init__(self, player)
        self.client = Client(self.tokenChanged) 
        self.breadcrumb = [('root', 'root')]
        self.files = []
        self.raw = 0
        
    def stop(self):
        return super().stop()

    def start(self):      
        return super().start()

    def makeLoginLayout(self):
        url = self.client.login()
        img = self.player.getQRCodeImg({
            "content": url,
            "bg": "#ffffff",
            "fg": "#000000"
        })
        controls = [
            {'type':'label', 'height': 40, 'name':'阿里云 App 扫码登录'},
            {
                'type':'image',
                'name':'img',
                'height': 300, 
                'width': 300, 
                'value': 'data:image/png;base64,' + img
            },
            {'type':'space'}
        ]
        return controls

    def makeBreadcrumb(self):
        return [{
            'type':'link',
            'name': f'{i}_{item[0][:25]}', # limit name length
            'textColor': '#000000', 
            'fontSize': 13,
            'width': 100,
            '@click': 'onBreadcrumbClicked'
        } for (i, item) in enumerate(self.breadcrumb)] + [{'type':'space', 'width': -1}]
        

    def makeLayout(self):
        itemlayout = [
            [
                {
                    'type':'label',
                    'name':'name',
                    'textColor': '#000000', 
                    'fontSize': 15,
                    'width': 1.0,
                }
            ]
        ]
        self.files = sorted([{
            "name": f'[{i["name"]}]' if i["type"] == "folder"  else i["name"],
            "type": i["type"],
            "url": i["url"],
            "file_id": i["file_id"],
            "drive_id": i["drive_id"]
        } for i in self.client.get_file_list(self.breadcrumb[-1][1])], key=lambda x: x['name'])
        header = {
            'group': [
                {'type':'label', 'height': 40, 'width': 80, 'name':'阿里云盘'},
                {'type':'space', 'width': -1},
                {
                    'group' : [
                        {
                            'type':'radio',
                            'name':'原文件(支持杜比)',
                            'height': 40, 
                            'textColor': '#444444', 
                            'fontSize': 14,
                            ':value': 'raw'
                        },
                        {
                            'type':'radio',
                            'name':'1080P(流畅)',
                            'height': 40, 
                            'textColor': '#444444', 
                            'fontSize': 14,
                            'value': 1
                        }
                    ]   
                },
                {
                    'type':'link',
                    'name':'退出登录',
                    'textColor': '#000000', 
                    'fontSize': 15,
                    'width': 80,
                    '@click': 'onLogoutClicked'
                }
            ],
            'height': 40
        }
        controls = [
            header,
            {
                'group': self.makeBreadcrumb(),
                'height': 30
            },            
            {
                'type':'list',
                'name':'list',
                'itemheight': 30, 
                'itemlayout': itemlayout,
                'value': self.files,
                '@dblclick': 'onFileDblClicked'
            },
        ]
        print(controls)
        return controls

    def updateLayout(self):
        controls = self.makeLayout() if self.client.token else self.makeLoginLayout()
        self.player.updateLayout("main", controls)
        
    def show(self):
        controls = self.makeLayout() if self.client.token else self.makeLoginLayout()
        self.doModal('main',900, 500,'测试', controls)

    def tokenChanged(self, msg=None):
        if msg is not None:
            self.player.toast("main", msg)
        self.updateLayout()

    def onLogoutClicked(self, page, control):
        self.client.logout()

    def onBreadcrumbClicked(self, page, control):
        items = control.split("_")
        index = int(items[0]) + 1
        self.breadcrumb = self.breadcrumb[:index]
        self.updateLayout()

    def onFileDblClicked(self, page, control, item):
        file = self.files[item]
        if file["type"] == "folder":
            self.breadcrumb.append((file["name"].strip("[]"), file["file_id"]))
            self.updateLayout()
        elif file["type"] == "file":
            print(file["name"])
            print(file["url"])
            url = file["url"]
            if not self.raw:
                print("get preview url")
                url = self.client.get_video_preview_play_info(file["file_id"], file["drive_id"])
            line = url
            while line:
                print(line[:512])
                line = line[512:]

            headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36', 'referer': 'https://www.aliyundrive.com/'}
            try:
                self.player.play(url, caption=file["name"], headers=headers)
            except:
                self.player.play(url, headers=headers)
    
def newPlugin(player:StellarPlayer.IStellarPlayer,*arg):
    plugin = myplugin(player)
    return plugin

def destroyPlugin(plugin:StellarPlayer.IStellarPlayerPlugin):
    plugin.stop()
