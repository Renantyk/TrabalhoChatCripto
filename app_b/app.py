from flask import Flask, request
import requests
import os
from rsa import RSA
from threading import Thread
import threading
from sha256 import SHA256


app = Flask(__name__)
rsa = RSA()
chat_log = []


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
    sha = SHA256(dados["mensagem"])
    hashreceber = sha.criptografar()
    
    if (dados["hash"] != hashreceber):
        return{"Mensagem alterada"}
    
    criptografada = dados["mensagem"]
    msg = rsa.descriptografar(criptografada, chave_privada)
    chat_log.append(f"Remoto: {msg}")
    print("\n".join(chat_log))
    return {"status": "Recebido"}, 200

def enviar():
    while True:
        with open("app_b/keys/chave_publica_a.txt", "r") as f:
            chave_publica_dest = f.read()
        texto = input("Você: ")
        chat_log.append(f"Você: {texto}")
        criptografada = rsa.criptografar(texto, chave_publica_dest)
        hashenvio = SHA256(texto)
        hashenvio = hashenvio.criptografar()
        requests.post("http://localhost:5000/receber", json={"mensagem": criptografada,
                                                             "hash": hashenvio})
        #print("mensagem enviada")
        print(f"msg criptografada: {criptografada}")

@app.route("/receberpublic", methods=["POST"])
def receberpublica():
    with open("app_b/keys/chave_publica_a.txt", "w") as f:
        f.write(request.get_json()["chave_publica"])
    return "chave recebida"


if __name__ == "__main__":
    threading.Thread(target=enviar, daemon=True).start()
    app.run(port=5001)