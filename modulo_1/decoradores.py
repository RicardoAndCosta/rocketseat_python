# Decorador é um tipo espscial de função permitindo modificar ou estender comportamentos de outras funções
# COnseguimos adicionar funcionalidades sem ter q alterar o código original da função

from typing import Any


def meu_decorador(func):
    def wrapper():
        print("Antes da função ser chamada")
        func()
        print("Depois da função ser chamada")
    return wrapper

# para chamar o decorador passamos antes da função seguido do arroba 
@meu_decorador
def minha_funcao():
    print("Minha funçõa foi chamada")

minha_funcao()

# podemos ter um decorador como classe
class MeuDecoradorDeClasse:
    def __init__(self, func) -> None:
        self.func = func
        
    def __call__(self, *args: Any, **kwds: Any) -> Any:
        print("Antes da função ser chamada (decorador de classe)")
        self.func()
        print("Depois da função ser chamada (decorador de classe)")

@MeuDecoradorDeClasse
def segunda_funcao():
    print("Segunda função foi chamada")

segunda_funcao()