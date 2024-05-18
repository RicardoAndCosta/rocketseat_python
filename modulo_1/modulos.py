# São arquivos que contém definições e instruções que podem ser reutilizados por outros programas
# podem ser nativos do Python ou criado por outros programadores 
# Para utilizar um módulo devemos importar atráves do comando IMPORT nome_do_modulo
# Para exportar um módulo criado por nós

print("Exemplo de importação de um módulo padrão:")

# desta forma importamos o módulo todo NÃO É RECOMENDADO 
# pois se um outro ponto sofre uma atualização pode prejudicar o seu programa
import math 

# desta forma importamos apenas o que vamos utilizar É O MAIS RECOMENDADO
from math import sqrt

raiz_quadrada = math.sqrt(25)
print(f"A raiz quadrada de 25 é {raiz_quadrada}")

print("\nExemplo de criação e utilização de um módulo personalizado")
from meu_modulo import saudacao, dobro

mensagem = saudacao("Ricardo")
resultado_dobro = dobro(4)
print(mensagem)
print(resultado_dobro)
