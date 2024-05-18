# Lista é uma coleção de elementos ORDENADOS e MUTAVEIS 
# pode ser qualquer coisa String, números, objetos, booleanos e etc
# pode conter diversos tipos de elementos dentro da mesma lista
# e são ordenados por um índice que SEMPRE se inicia pelo elemento 0 mesmo que o elemento seja outro número
# e devem estar dentro de []

# Declaração
minha_lista = [1, 2, 3 , 4, 5, "ricardo", True, False]

# Exibindo a lista completa
print("Minha lista de elementos", minha_lista)

# Exibindo apenas um elemento da lista 
print("Minha lista de elementos no indice 0", minha_lista[0])

# Exibindo partes de uma lista
print("Intervalo da minha lista ", minha_lista[1:7]) 
print("Do inicio até onde eu quero", minha_lista[:6])
print("De onde eu quero até o final", minha_lista[2:])

# Mutavel, posso alterar um elemento passando diretamente a posição dele na lista
minha_lista[0] = "python"
print("Minha lista de elementos", minha_lista)

# Metodos 

# append() Adiona um elemento no final da lista 
minha_lista.append(6)
print("Após append", minha_lista)

# index() retorna o índice de um elemento 
minha_lista.index(6)
print("Índice do elemento 6:", minha_lista)

# insert() insere um elemento em um índice específico, passamos o índice e depois o novo valor
minha_lista.insert(2, "novo elemento")
print("Após insert", minha_lista)

# pop() remove e retorna o elemento de um ÍNDICE especifico
elemento_removido = minha_lista.pop(3)
print("Elemento removido", elemento_removido)
print("Após pop", minha_lista)

# remove() remove o primeiro elemento com o VALOR  especificado
minha_lista.remove(True)
print("Após remove(True", minha_lista)

# sort() organiza a lista em ordem crescente
minha_lista.sort()

# vai retornar um erro pq a lista tem diversos tipos de elemento String e booleano
print("Após sort()", minha_lista)

minha_lista_numeros = [2, 5, 9, 1, 500, 65, 95, 12]
minha_lista_numeros.sort()
print("Após sort() numa lista de números: ", minha_lista_numeros)