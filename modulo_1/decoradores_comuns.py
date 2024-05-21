# @classmethod 
# @staticmethod

class MinhaClasse:
    valor = 10 # Atributo de classe

    def __init__(self, nome) -> None:
        self.nome = nome # Atributo da instância

    def metodo_instancia(self):
        return f"Método de instância chamado para {self.nome}"
    
    @classmethod # faz com que o metodo seja da classe e não da instancia e recebe a referencia da classe
    def metodo_classe(cls):
        return f"Método de classe chamado para valro={cls.valor}"

    @staticmethod # vai adicionar um comportamento estatico ao metodo e não recebe a referencia da classe
    def metodo_estatico():
        return "Método estático da classe"


obj = MinhaClasse(nome="Calsse Exemplo")
print(obj.metodo_instancia())
print(MinhaClasse.metodo_classe())
print(MinhaClasse.metodo_estatico())

class Carro:
    def __init__(self, marca, modelo, ano) -> None:
        self.marca = marca
        self.modelo = modelo
        self.ano = ano

    @classmethod
    def criar_carro(cls, configuracao):
        marca, modelo, ano = configuracao.split(",")
        return cls(marca, modelo, int(ano))
    

configuracao1 = "Toyota,Corolla,2022"
carro1 = Carro.criar_carro(configuracao1)
print(F"Marca: {carro1.marca}\nModelo: {carro1.modelo}\nAno: {carro1.ano}")

class Matematica:

# Acessa ao metodo sem precisar instanciar o obj 
    @staticmethod
    def somar(a, b):
        return a + b
    
print(Matematica.somar(a=10, b=15))
