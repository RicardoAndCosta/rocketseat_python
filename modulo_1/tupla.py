# Tuplas são muito parecidas com as listas 
# Tupla é uma coleção de elementos ORDENADOS e IMUTAVEIS 
# pode ser qualquer coisa String, números, objetos, booleanos e etc
# pode conter diversos tipos de elementos dentro da mesma lista
# e são ordenados por um índice que SEMPRE se inicia pelo elemento 0 mesmo que o elemento seja outro número
# e devem estar dentro de ()

# Criando a tupla
minha_tupla = (1, 2, 2, 3, 4)
print("Minha Tupla:", minha_tupla)
print("Elemento Tupla:", minha_tupla[2])
print("Último elemento da Tupla:", minha_tupla[-1])

# count() retorna uma quantidade de vezes que um elemento aparece na tupla
contagem = minha_tupla.count(2)
print("Quantas vezes aparece o número 2 na tupla é ", contagem)

# index() retorna o indice de um elemento
indice = minha_tupla(3)
print("O índice da primeira ocorrência do elemento 3 é", indice)