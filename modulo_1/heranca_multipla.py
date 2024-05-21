# É quando uma classe herda de mais de uma classe mãe 

class Animal:
    def __init__(self, nome) -> None:
        self.nome = nome

    def emitir_som(self):
        pass

class Mamifero(Animal):
    def amamentar(self):
        return f"{self.nome} está amamentando."
    
class Ave(Animal):
    def voar(self):
        return f"{self.nome} está voando."

# Para isso passamos as classes dentro do paramentro de herança   
class Morcego(Mamifero, Ave):
    def emitir_som(self):
        return "Morcego emitem sons ultrassônicos" 
    

morcego = Morcego(nome="Batman")

# Acessando métodos da classe base "Animal"
print("Nome do morcego:", morcego.nome)
print("Som do morcego:", morcego.emitir_som())

# Acessando métodos das classes "Mamiferos" e "Ave"
print("Morcego amamentando:", morcego.amamentar())
print("Morcego voando:", morcego.voar())