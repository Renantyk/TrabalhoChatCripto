from random import randint, choice
from math import gcd

class RSA():
    
    p = 0
    q = 0
    totiente_n = 0
    n = 0
    e = 2
    d = 2
    texto_criptografado = False
    
    
    def criar_chaves(self, testar = False):
        if not testar:
            primos = self._gerarprimos()
            self.p = choice(primos)
            while not self._isprimo(self.p):
                self.p = choice(primos)
            
            self.q = choice(primos)
            while not self._isprimo(self.q) and self.q == self.p:
                self.q = choice(primos)
        
        else:
            self.p = 17
            self.q = 23
        
        
        self.totiente_n = (self.p - 1) * (self.q - 1)
        self.n = self.p * self.q
        
        while 1 < gcd(self.e, self.totiente_n) and self.e < self.totiente_n:
            self.e += 1
        
        while ((self.d * self.e) % self.totiente_n != 1) and self.d < self.totiente_n:
            self.d += 1

        return {
            "private_key": f"{self.e}, {self.n}",
            "public_key": f"{self.d}, {self.n}"
        }
    
    def criptografar(self, texto, chave):
        chaves = chave.split(",")
        self.e = int(chaves[0])
        self.n = int(chaves[1])
        
        
        ascii = self._transformar_em_ascii(texto)
        retorno = ""
        
        for m in ascii:
            retorno += f"{(m ** self.e) % self.n},"
        
        retorno = retorno[:len(retorno) - 1]
        
        self.texto_criptografado = retorno
        
        return retorno
    
    
    def descriptografar(self, texto, chave):
        
        
        chaves = chave.split(",")
        d = int(chaves[0])
        n = int(chaves[1])
        
        texto = texto.split(",")
        
        
        texto_descript = ""
        i = 0
        for t in texto:
            print(f"descriptografando: {i/len(texto)*100}%", end="\r")
            t = t.replace("\x00", "")
            m = (int(t) ** d) % n
            texto_descript += chr(m)
            i+=1
        print()
                
        return texto_descript
        
                
    
    
    def _transformar_em_ascii(self, texto):
        texto_bytes = ""
        if (type(texto) == bytes):
            texto_bytes = bytearray(texto)
        else:
            texto_bytes = bytearray(texto, encoding="utf-8")
        
        retorno = []
        for a in texto_bytes:
            retorno.append(int(a))
        
        return retorno
            
        
    
    def _gerarprimos(self):
        x = 2
        y = randint(2, 10**4)
        retorno = []
        
        for i in range(x-1, y):
            print(f"Gerando primos {i/y*100}%", end="\r")
            if self._isprimo(i):
                retorno.append(i)
        print()
        return retorno
    
    
    def _isprimo(self, num):
        retorno = True
        for divisor in range(1, num):
            if num % divisor == 0 and divisor != 1:
                retorno = False
                break
        
        return retorno

    
    def _gerar_arquivo_chaves(self):
        
        with open("app_a/keys/chave_publica.txt", "w") as c:
            c.write(f"{self.e},{self.n}")
        
        with open("app_a/keys/chave_privada.txt", "w") as c:
            c.write(f"{self.d},{self.n}")