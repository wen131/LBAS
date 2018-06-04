from flask import Flask,render_template,Response
import sys
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)

@app.route('/')
def greeting():
  image = open("%s.gif"%(FLAG,),'rb')
  resp = Response(image,mimetype="image/png")
  return resp

if __name__ == '__main__':
  FLAG=sys.argv[1]
  app.run(host='0.0.0.0')
