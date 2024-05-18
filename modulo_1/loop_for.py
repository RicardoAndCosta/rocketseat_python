# São blocos de códigos que serão executados enquanto uma condição for verdadeira
# São utilizados para automatizar tarefas repetitivas ou realizar uma ação por uma quantidade de vezes

# FOR
print("FOR utilizando lista")
lista = [1, 2, 3, 4, 5]
for elemento in lista:
    print(elemento)

print("FOR utilizando tupla")
tupla = (1, 2, 3, 4, 5)
for elemento in tupla:
    print(elemento)


pessoa = {"nome": "João", "idade": 30, "cidade": "São Paulo"}
print("FOR utilizando dicionário - chave")
for chave in pessoa.keys():
    print(chave)

# \n pula linha
print("\nFOR utilizando dicionário - valores")
for valor in pessoa.values():
    print(valor)

print("\nFOR utilizando dicionário - chave valor")
for chave, valor in pessoa.items():
    print(f"{chave}: {valor}")

# range() retorna um intervalo numérico em formato de lista passamos o primeiro elemento e quantos índices terá
# [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
print("\nUtilizando range()")
print(list(range(0, 10)))

# FOR com range()
print("\nUtilizando for com range()")
for numero in range(5):
    print("Numero:", numero)

# range() com len() - len() retorna o índice da lista
print("\nUtilizando range() com len()")
lista = [1, 2, 3, 4, 5]
for indice in range(0, len(lista)):
    print("Indice:", indice)
    print("Elemento:", lista[indice])

# enumerate() retornar o indice e o valor juntos
lista_enumerate = ["a", "b", "c"] 
for indice, valor in enumerate(lista_enumerate):
    print(f"{indice}: {valor}")