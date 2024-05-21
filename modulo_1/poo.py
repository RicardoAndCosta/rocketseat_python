# Mas basicamente o que você precisa saber é que essas linguagens de programação
# como Python, Java, C++, C Sharp, Ruby e muitas outras
# oferecem suporte nativo à programação orientada a objetos.
# E elas permitem que os programadores criem softwares de forma modular, reutilizável
# e mais fácil de se entender e manter, seguindo os princípios e conceitos
# da programação orientada a objetos que nós vamos ver em seguida.
# Então, programação orientada a objetos, ou POO, é basicamente um paradigma de programação
# que se baseia na organização dos programas em torno de objetos.
# E a gente vai ver a definição de objeto, mas basicamente objetos são instâncias de classes.

# Classe Exemplo
class Pessoa:
    # metodo construtor onde DEF dentro de uma classe ele não é mais uma função mas sim um metodo
    # __INIT__ é padrão e dentro do () passamos os parametros onde SELF sempre irá se referenciar 
    # -> None vem por padrão não é obrigatório mas a comunidade mantém
    def __init__(self, nome, idade) -> None:
        self.nome = nome
        self.idade = idade
    
    def saudacao(self):
        return f"Olá, meu nome é {self.nome} e eu tenho {self.idade} anos."

# Objetos
# Para instanciar um objeto chamamos a classe passando os paramentros
pessoa1 = Pessoa("Alice",30)

# Acessando os métodos
print("Nome:", pessoa1.nome)
print("Idade:", pessoa1.idade)
mensagem = pessoa1.saudacao()
print(mensagem)

pessoa2 = Pessoa("Rodrigo", 30)
mensagem = pessoa2.saudacao()
print(mensagem)

# algumas das principais vantagens em utilizar objetos é a reutilização dos códigos e seus pilarem
# Herança, encapsulamento e polimorfismo 
# algumas das desvantagens tenhos a complexidade q dependendo do projeto pode não ser viavél onde alguns 
# projeto pode não ser necessário.