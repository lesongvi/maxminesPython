import threading
import os
import ctypes
import time
import random
import binascii
import json
import websocket
import queue

SITEKEY = "ymIS4YMJ2zd7TtJcTTkQvvrrwGX9eDgLu4zBo5Rq"

LIBCH = "libmaxmines.dll"

THREADS = int(os.cpu_count() / 2)

DEBUG = False

TRACE = False

MMVERSION = 8

SocketWS = websocket.WebSocket()
QSend = queue.Queue()
Job = {
  "job_id": "",
  "blob": b"",
  "target": b"",
  "jobChanged": 0
}

def ProcSvr(Msg):
  global Job
  MsgData = json.loads(Msg)

  if MsgData["vimsg"] == "error":
    print("[E][SVR] MaxMines Error: " + MsgData["params"]["error"])

  elif MsgData["vimsg"] == "banned":
    print("[E][SVR] Banned. Oops.")

  elif MsgData["vimsg"] == "invalid_msg":
    print("[E][SVR] Invalid message!? What am I sending?")

  elif MsgData["vimsg"] == "invalid_hash":
    print("[E][SVR] Invalid hash. Things are going worse.")

  elif MsgData["vimsg"] == "open":
    print("[I][SVR] MaxMines opened")

  elif MsgData["vimsg"] == "authed":
    print("[I][SVR] Authed")

  elif MsgData["vimsg"] == "hash_accepted":
    print("[I][SVR] Hash Accepted %d" % MsgData["params"]["hashes"])

  elif MsgData["vimsg"] == "job":
    print(MsgData["params"]['blob'])
    print("[I][SVR] Got job")
    target = binascii.unhexlify(MsgData["params"]["target"])
    targetFull = bytearray(8)
    if len(target) <= 8:
      for i in range(len(target)):
        targetFull[len(targetFull) - i - 1] = target[len(target) - i - 1]
      for i in range(len(targetFull) - len(target)):
        targetFull[i] = 0xff
    else:
      targetFull = target
    if DEBUG:
      print("[D][SVR] blob = " + MsgData["params"]["blob"])
      print("[D][SVR] target = " + binascii.hexlify(targetFull).decode())
    Job = {
      "job_id": MsgData["params"]["job_id"],
      "blob": binascii.unhexlify(MsgData["params"]["blob"]),
      "target": targetFull,
      "jobChanged": (1 << THREADS) - 1
    }

  elif MsgData["vimsg"] == "verify":
    print("[I][SVR] Verify requested")
    if DEBUG:
      print("[D][SVR] blob = " + MsgData["params"]["blob"])
      print("[D][SVR] nonce = " + MsgData["params"]["nonce"])
      print("[D][SVR] result = " + MsgData["params"]["result"])

    Ret = {
      "vimsg": "verified",
      "params": {
        "verify_id": MsgData["params"]["verify_id"],
        "verified": True,
        "result": MsgData["params"]["result"]
      }
    }
    QSend.put(Ret)

  else:
    print("[W][SVR] Unknown message " + Msg)

  return

def MeetsTarget(result, target):
  for i in range(len(target)):
    ri = len(result) - i - 1
    ti = len(target) - i - 1
    if result[ri] > target[ti]: return False
    elif result[ri] < target[ti]: return True
  return False

def WorkerFunc(WorkerNo):
  global Job
  print("[I][CLI] %d: Worker thread ready" % WorkerNo)
  while Job["job_id"] == "": time.sleep(0.1)

  try:
    ctypes.cdll.LoadLibrary(LIBCH)
    libch = ctypes.cdll.libmaxmines
    libch.libmaxmines_create()
    libch.libmaxmines_pInput.restype = ctypes.POINTER(ctypes.c_char * 84)
    libch.libmaxmines_pOutput.restype = ctypes.POINTER(ctypes.c_char * 32)
    blob = libch.libmaxmines_pInput().contents
    result = libch.libmaxmines_pOutput().contents
  except:
    print("[F][CLI] %d: libmaxmines could not be initialized" % WorkerNo)
    return
  if DEBUG: print("[D][CLI] %d: libmaxmines initialized from %s" % (WorkerNo, LIBCH))

  while True:
    if Job["jobChanged"] & 1 << WorkerNo:
      if DEBUG: print("[D][CLI] %d: New job" % WorkerNo)

      for i in range(len(Job["blob"])): blob[i] = Job["blob"][i]

      #type(blob[0]) == bytes, type(blob[0][0]) == int
      if blob[0][0] > 7:
        Hash = libch.libmaxmines_hash_v2_Q
      elif blob[0][0] == 7:
        Hash = libch.libmaxmines_hash_v1_Q
      else:
        Hash = libch.libmaxmines_hash_v0_Q

      Job["jobChanged"] &= ~(1 << WorkerNo)

    nonce = random.randint(0, 0xffffffff).to_bytes(length = 4, byteorder = "big")
    for i in range(4):
      blob[i + 39] = nonce[i]

    Hash()

    if MeetsTarget(result.raw, Job["target"]):
      print("[I][CLI] %d: Hash found" % WorkerNo)
      if DEBUG:
        print("[D][CLI] nonce = " + binascii.hexlify(nonce).decode())
        print("[D][CLI] result = " + binascii.hexlify(result).decode())
      Ret = {
        "vimsg":"solved",
        "job_id": Job["job_id"],
        "nonce": binascii.hexlify(nonce).decode(),
        "result": binascii.hexlify(result).decode()
      }
      QSend.put(Ret)
  try:
    libch.libmaxmines_destroy()
  except:
    pass
  print("[I][CLI] %d: Worker thread stopped" % WorkerNo)

def WSRecvFunc():
  global SocketWS
  print("[I][WS] Recv thread started")
  
  try:
    Server = "wss://roleplay.vn:33347/"
    print("[I][WS] Chosen server is " + Server)
    SocketWS.connect(Server)
  except:
    print("[E][WS] Connect failed, end thread")
    return
  print("[I][WS] Connected")

  Workers = [None] * THREADS
  for i in range(THREADS):
    Workers[i] = threading.Thread(name = "Worker %d" % i, target = WorkerFunc, args = (i, ))
    Workers[i].setDaemon(True)
    Workers[i].start()

  Ret = {
    "vimsg": "handshake",
    "pool": "services.songvi.ml",
    "coin": "xmr",
    "login": SITEKEY,
    "key": SITEKEY,
    "password": "",
    "userid": "",
    "version": MMVERSION,
    "goal": 0,
  }

  QSend.put(Ret)

  while True:
    try:
      Msg = SocketWS.recv()
    except Exception as e:
      print(e)
      break
    if not Msg: break
    if DEBUG: print("[D][WS] RECV " + Msg)
    ProcSvr(Msg)

  try:
    SocketWS.close()
  except:
    pass
  print("[I][WS] Recv thread stopped")

def dohandshake(self, header, key=None):
    
        logging.debug("Begin handshake: %s" % header)
        
        handshake = self.handshake
        
        for line in header.split('\r\n')[1:]:
            name, value = line.split(': ', 1)
            
            if name.lower() == "sec-websocket-key":
                
                handshake = handshake % { 'pool' : 'services.songvi.ml' }
                handshake = handshake % { 'key' : SITEKEY }
                handshake = handshake % { 'coin' : 'xmr' }
                handshake = handshake % { 'password' : '' }
                handshake = handshake % { 'userid' : None }
                handshake = handshake % { 'versioning' : 8 }
                handshake = handshake % { 'goal' : 0 }

        logging.debug("Sending handshake %s" % handshake)
        SocketWS.send(handshake)
        return True

def sendMessage(self, s):
        """
        Encode and send a WebSocket message
        """

        message = ""
        
        b1 = 0x80

        if type(s) == unicode:
            b1 |= TEXT
            payload = s.encode("UTF8")
            
        elif type(s) == str:
            b1 |= TEXT
            payload = s

        message += chr(b1)

        b2 = 0
        
        length = len(payload)
        if length < 126:
            b2 |= length
            message += chr(b2)
        
        elif length < (2 ** 16) - 1:
            b2 |= 126
            message += chr(b2)
            l = struct.pack(">H", length)
            message += l
        
        else:
            l = struct.pack(">Q", length)
            b2 |= 127
            message += chr(b2)
            message += l

        message += payload

        SocketWS.send(str(message))

def decodeCharArray(self, stringStreamIn):
    
        byteArray = [ord(character) for character in stringStreamIn]
        datalength = byteArray[1] & 127
        indexFirstMask = 2

        if datalength == 126:
            indexFirstMask = 4
        elif datalength == 127:
            indexFirstMask = 10

        masks = [m for m in byteArray[indexFirstMask : indexFirstMask+4]]
        indexFirstDataByte = indexFirstMask + 4
        
        decodedChars = []
        i = indexFirstDataByte
        j = 0
        
        while i < len(byteArray):
        
            decodedChars.append( chr(byteArray[i] ^ masks[j % 4]) )
            i += 1
            j += 1

        return decodedChars

def main():
  global SocketWS
  print("[I] PyMiner Dev - Running with %d threads" % THREADS)
  print("[I] For testing purposes only - it's unstable")
  if TRACE: websocket.enableTrace(True)

  if not THREADS:
    print("[F][WS] No usable core. Please change THREADS to a constant.")
    return

  WSRecv = threading.Thread(name = "WSRecv", target = WSRecvFunc)
  WSRecv.setDaemon(True)
  WSRecv.start()

  try:
    print("[I][WS] Send thread ready")
    while WSRecv.isAlive():
      try:
        Msg = json.dumps(QSend.get(block = False))
      except queue.Empty:
        time.sleep(0.1)
        continue
      try:
        SocketWS.send(Msg.encode(encoding = "ascii"))
        if DEBUG: print("[D][WS] SEND " + Msg)
      except:
        print("[E][WS] SEND FAILED" + Msg)
  except KeyboardInterrupt:
    print("[I] ^C Received")
  quit(0)

if __name__ == "__main__":
  main()