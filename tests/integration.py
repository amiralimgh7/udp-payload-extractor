"""Generate isolated synthetic captures; verify exact hashes and output encoding."""
from pathlib import Path
import struct,subprocess,tempfile,json,hashlib

binary=Path(__file__).resolve().parents[1]/'udp_payload_extractor'
if not binary.exists():binary=binary.with_suffix('.exe')
def frame(key):
    payload=b'#'+key+b'#'
    ethernet=b'\0'*12+b'\x08\x00'
    ip=bytearray(20);ip[0]=0x45;ip[2:4]=struct.pack('!H',28+len(payload));ip[9]=17;ip[12:14]=b'\x0a\x0a'
    udp=struct.pack('!HHHH',1,2,len(payload)+8,0)
    return ethernet+ip+udp+payload
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    for endian,magic in [('<',0xa1b2c3d4),('>',0xa1b23c4d)]:
        cap=root/'test.pcap';out=root/'out.jsonl'
        keys=[b'quoted"\\key',b'',b'a\0b']
        with cap.open('wb') as f:
            f.write(struct.pack(endian+'IHHIIII',magic,2,4,0,0,65535,1))
            for key in keys:
                packet=frame(key);f.write(struct.pack(endian+'IIII',0,0,len(packet),len(packet)));f.write(packet)
        for workers in (1,4):
            subprocess.run([str(binary),str(cap),str(out),str(workers)],check=True)
            rows=[json.loads(line) for line in out.read_text().splitlines()]
            assert len(rows)==len(keys)
            for row,key in zip(rows,keys):
                digest=hashlib.sha1(key).digest()
                for _ in range(9999):digest=hashlib.sha1(digest).digest()
                assert row=={'key':key.decode('latin1'),'sha1':digest.hex()}
        cap.write_bytes(cap.read_bytes()[:-1])
        assert subprocess.run([str(binary),str(cap),str(out)],capture_output=True).returncode!=0
print('PCAP endian, truncation, JSON escaping and parallel hash tests passed')
