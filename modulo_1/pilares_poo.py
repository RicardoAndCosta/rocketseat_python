# Herança
# Na herança temos um classe q será a classe filho que herda da classe mãe/pai os seus atributos e metodos
# Exemplo de herança
print("\nExemplo de herança:")
class Animal:
    def __init__(self,nome) -> None:
        self.nome = nome

    def andar(self):
        print(f"O animal {self.nome} andou")
        return
    
    def emitir_som(self):
        pass

# passando a classe mãe dentro do parametro faz a herança
# Polimorfismo
# quando uma classe filho modifica um metodo herdado temos o polimorfismo pois neste exemplo todos os animais
# emitem som mas cada animal emite o SEU TIPO DE SOM diferente do outro objeto sendo que iremos chamar o metodo
# da mesma forma independentemente do objeto.
class Cachorro(Animal):
    def emitir_som(self):
        return "Au, au"
    
class Gato(Animal):
    def emitir_som(self):
        return "Miau!"

dog = Cachorro("rex")
cat = Gato("felix")

print("\nExemplo de polimorfismo")
animais =[dog, cat]
for animal in animais:
    print(f"{animal.nome} faz: {animal.emitir_som()}")

# Encapsulamento
# Uso de atributos privados evitando que os atributos sejam acessados e modificados erroneamente e diretamente
print("\nExemplo de encapsulamento")
class ContaBancaria:
    def __init__(self, saldo) -> None:
        self.__saldo = saldo # Atributo Privado colocando 2 underlines antes do nome do atributo

    def depositar(self, valor):
        if valor > 0:
            self.__saldo += valor

    def sacar(self, valor):
        if valor > 0 and valor <= self.__saldo:
            self.__saldo -= valor
    
    # Desta forma o atributo não é acessado diretamente mantenho ele protegido pois o metodos q acessa ele
    def consultar_saldo(self):
        return self.__saldo

conta = ContaBancaria(1000)
print(f"Saldo da conta bancária: {conta.consultar_saldo()}")
conta.depositar(500)
print(f"Saldo da conta bancária: {conta.consultar_saldo()}")
conta.depositar(-500)
print(f"Saldo da conta bancária: {conta.consultar_saldo()}")
conta.sacar(200)
print(f"Saldo da conta bancária: {conta.consultar_saldo()}")

conta_da_maria = ContaBancaria(50)

# Abstração
# Uma classe abstrata é um molde para criar outras classes não sendo possivel criar objetos diretamente dela
print("\nExemplo de Abstração:")
from abc import ABC, abstractmethod

class Veiculo(ABC):
    
    # um metodo abstrata não é instanciada nada obrigando assim que a classe derivada tenha q implementar 
    # senão ela não será criada    
    @abstractmethod
    def ligar(self):
        pass

    @abstractmethod
    def desligar(self):
        pass

class Carro(Veiculo):
    def __init__(self) -> None:
        pass

    def ligar(self):
        return "Carro ligado usando a chave"
    
    def desligar(self):
        return "Carro desligado usando a chave"

carro_amarelo = Carro()
print(carro_amarelo.ligar())
print(carro_amarelo.desligar())