from flask import Flask, request
import requests
import os
from rsa import RSA
from threading import Thread


app = Flask(__name__)
rsa = RSA()


if not os.path.exists("app_b/keys/chave_privada.txt"):
    rsa_criar = rsa.criar_chaves(True)
    requests.post("http://localhost:5000/receberpublic", json={"chave_publica": rsa_criar["public_key"]})

    with open("app_b/keys/chave_privada.txt", "w") as f:
        f.write(rsa_criar["private_key"])

    
@app.route("/receber", methods=["POST"])
def receber():
    with open("app_b/keys/chave_privada.txt", "r") as f:
        chave_privada = f.read()
    dados = request.get_json()
    criptografada = dados["mensagem"]
    msg = rsa.descriptografar(criptografada, chave_privada)
    print(f"\n {msg}")
    return {"status": "Recebido"}, 200

def enviar():
    with open("app_b/keys/chave_publica_a.txt", "r") as f:
        chave_publica_dest = f.read()
    texto = "hesauh"
    criptografada = rsa.criptografar(texto, chave_publica_dest)
    requests.post("http://localhost:5000/receber", json={"mensagem": criptografada})
    print("mensagem enviada")

@app.route("/receberpublic", methods=["POST"])
def receberpublica():
    with open("app_b/keys/chave_publica_a.txt", "w") as f:
        f.write(request.get_json()["chave_publica"])
    return "chave recebida"


if __name__ == "__main__":
    app.run(port = 5001)
    enviar()