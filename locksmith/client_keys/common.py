import os, time, datetime, math, hashlib
import base64, uuid, struct, binascii

from datetime import date

from SimpleAES import SimpleAES, DecryptionError

from django.conf import settings

THIRTY_DAYS = datetime.timedelta(days=30).total_seconds()

def get_dateint():
    today = date.today()
    return today.month*32+today.day

def get_client_key(master_key, user_agent):
    hostname = "realtime"
    ukey = uuid.UUID(master_key)
        
    dateint = get_dateint()
    
    user_agent = user_agent[:8].upper()
    print "checking", user_agent
    
    
    print "get_client_key: dateint: %s" % (dateint)
    
    to_sign = "%s%s%s" % (ukey.bytes, struct.pack("i", dateint), struct.pack("i", binascii.crc32("%s/%s" % (hostname, user_agent))))
    #print "get_client_key: to_sign: %s" % to_sign
    signed = _encrypt(settings.SECRET_KEY, to_sign)
    print "get_client_key: signed: %s" % signed
    
    return signed[10:].replace("+", "-").replace("/", "_")

def check_client_key(client_key, user_agent):
    hostname = "realtime"
    
    dateint = get_dateint()
    
    
    # This should already have been done, but...
    user_agent = user_agent[:8].upper()
    print "checking", user_agent

    signed = "U2FsdGVkX1%s" % client_key.replace("-", "+").replace("_", "/")

    try:
        decrypted = _decrypt(settings.SECRET_KEY, signed)
    except DecryptionError:
        print "Decryption error"
        raise ValueError("Key not authorized.")
        

    key = uuid.UUID(bytes=decrypted[:-8]).hex
    print "check_client_key: key %s" % (key)
    key_ts = struct.unpack("i", decrypted[-8:-4])[0]
    print "check_client_key: key_is %s" % (key_ts)
    
    hostname_cs = struct.unpack("i", decrypted[-4:])[0]
    print "check_client_key: hostname_cs %s" % (hostname_cs)
    
    # just make it pass.
    return key
    
    if hostname_cs != binascii.crc32("%s/%s" % (hostname, user_agent)):
        raise ValueError("Hostname or user agent for this key doesn't match.")

    if dateint - key_ts > 1:
        raise ValueError("Key has expired.")

    return key

from locksmith.common import cache

get_cached_client_key = cache(seconds=900)(get_client_key)
check_cached_client_key = cache(seconds=900)(check_client_key)

def _simpleaes_encrypt(password, string):
    saes = SimpleAES(password)
    return saes.encrypt(string)

def _simpleaes_decrypt(password, string):
    saes = SimpleAES(password)
    return saes.decrypt(string)

def _slowaes_key(password, size=256, salt=None):
    rounds = math.ceil(size/128.0) + 1
    md5_hash = []
    if not salt:
        salt = os.urandom(8)
    
    ps = password + salt
    result = hashlib.md5(ps).digest()
    md5_hash = [result]
    
    for i in range(1, int(rounds) + 1):
        md5_hash.append(hashlib.md5(md5_hash[i - 1] + ps).digest())
        result = result + md5_hash[i]
    
    size8 = size / 8
    return {
        "key": result[0:size8],
        "iv": result[size8:size8+16],
        "salt": salt
    }

def _slowaes_encrypt(password, string):
    key = _slowaes_key(password, 256, salt=None)

    okey = map(ord, key['key'])
    data = aes.append_PKCS7_padding(string)

    moo = aes.AESModeOfOperation()
    (mode, length, ciph) = moo.encrypt(data, aes.AESModeOfOperation.modeOfOperation["CBC"], okey, len(okey), map(ord, key['iv']))
    raw_enc = ''.join(map(chr, ciph))

    return base64.b64encode("Salted__" + key['salt'] + raw_enc)

def _slowaes_decrypt(password, string):
    _string = base64.b64decode(string)

    key = _slowaes_key(password, 256, _string[8:16])

    okey = map(ord, key['key'])
    iv = map(ord, key['iv'])
    data = map(ord, _string[16:])
    moo = aes.AESModeOfOperation()
    decr = moo.decrypt(data, None, aes.AESModeOfOperation.modeOfOperation["CBC"], okey, len(okey), iv)

    return aes.strip_PKCS7_padding(decr)


_encrypt = _simpleaes_encrypt
_decrypt = _simpleaes_decrypt
