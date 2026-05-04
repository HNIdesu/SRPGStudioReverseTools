from argparse import ArgumentParser
from pathlib import Path
from Crypto.Hash import MD5
from Crypto.Cipher import ARC2

c1 = b"\x54\x94\xC1\x58\xF4\x4C\x92\x1B\xAD\xE0\x9E\x3A\x49\xD1\xC9\x92"

parser=ArgumentParser()
parser.add_argument("game_directory")
parser.add_argument("-o","--output",required=False ,default="key.bin")
args = parser.parse_args()

def decrypt1(input_buf:bytes,key:bytes)->bytes:
    h = MD5.new()
    h.update(key)
    key = h.digest()
    cipher = ARC2.new(key, ARC2.MODE_CBC, effective_keylen=128)
    decrypted_data = cipher.decrypt(input_buf)
    return decrypted_data

with open(Path(args.game_directory) / "environment.evs","br") as f:
    data = f.read(16)
    data = bytes(x ^ y for x, y in zip(data, c1))
    data += f.read()
    data = decrypt1(data, "_du".encode("utf-16le"))
with open(args.output,"bw") as f:
    f.write(data[16:32])
