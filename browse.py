import socket
import sys, os

def get(sport):
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

  s.bind(("10.0.0.1",sport))
  s.connect(("7.23.7.23",5000))

  s.sendall(b"GET / HTTP/1.1\r\n\r\n")
  s.close()

if __name__=="__main__":
  get(int(sys.argv[1]))
