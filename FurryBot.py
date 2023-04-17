from distutils.command.upload import upload
import time,requests,random,string,base64,hashlib
from json import loads
from threading import Thread
from itertools import cycle
from urllib3 import connection

print("FurryBot by NumbersTada")
un = input("Enter your Geometry Dash username: ")
pw = input("Enter your Geometry Dash password: ")
percentage = input("Enter your fake percentage (0 = None): ")

def request(self, method, url, body=None, headers=None):
    if headers is None:
        headers = {}
    else:
        # Avoid modifying the headers passed into .request()
        headers = headers.copy()
    super(connection.HTTPConnection, self).request(method, url, body=body, headers=headers)
connection.HTTPConnection.request = request

def comment_chk(*,username,comment,levelid,percentage,type):
	part_1 = username + comment + levelid + str(percentage) + type + "xPT6iUrtws0J"
	return base64.b64encode(xor(hashlib.sha1(part_1.encode()).hexdigest(),"29481").encode()).decode()
def xor(data, key):
	return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))
def gjp_encrypt(data):
	return base64.b64encode(xor(data,"37526").encode()).decode()
def gjp_decrypt(data):
	return xor(base64.b64decode(data.encode()).decode(),"37526")

def getGJUsers(target):
    data={
        "secret":"Wmfd2893gb7",
        "str":target
    }
    request =  requests.post("http://www.boomlings.com/database/getGJUsers20.php",data=data,headers={"User-Agent": ""}).text.split(":")[1::2]
    print(request)
    username = request[0]
    uuid = request[2]
    accountid = request[10]
    return (username,accountid,uuid)

def uploadGJComment(name,passw,comment,perc,level):
        try:
                accountid = getGJUsers(name)[1]
                gjp = gjp_encrypt(passw)
                c = base64.b64encode(comment.encode()).decode()
                chk = comment_chk(username=name,comment=c,levelid=str(level),percentage=perc,type="0")
                data={
                    "secret":"Wmfd2893gb7",
                    "accountID":accountid,
                    "gjp":gjp,
                    "userName":name,
                    "comment":c,
                    "levelID":level,
                    "percent":perc,
                    "chk":chk
                }
                return requests.post("http://www.boomlings.com/database/uploadGJComment21.php",data=data,headers={"User-Agent": ""}).text
        except:
                return "problem"
                
def randstring(length):
    chars = string.ascii_letters
    from os import urandom
    return "".join(chars[c % len(chars)] for c in urandom(length))

def commands(level):
    url=f"http://gdbrowser.com/api/comments/{level}?count=1"
    r=loads(requests.get(url).text)[0]
    u=r['username']
    com=r['content']
    perc=percentage

    msgcom = ['Hey uwu aww, couwd uwu wike my most wecent post? :3', 'Hey fuwwies :3', 'Pwease give me diswikes own thiws comment :3', 'WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW', 'UwU, i am a fuwwy :3', 'Daiwy chat iws awesome :3']
    coolstring = randstring(5)
    randcom = random.choice(msgcom)+' '+coolstring

    uploadGJComment(un,pw,randcom,perc,level)

lvl=input("Enter the ID of the level where the bot will run: ")

while 1:
    try:
        t=Thread(target=commands,args=(lvl,))
        t.start()
        time.sleep(28)
    except:
        print("Error")
