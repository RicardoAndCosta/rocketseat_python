# Dicionario é uma coleção NÃO ordenado de pares chave valor
# os valores são atribuidos as chaves quando usamos o : e são separados por , 

# Criando um dicionario
pessoa = {"nome": "Ricardo", "idade": 39, "cidade": "São Paulo"}
print("Meu dicionário:", pessoa)

# Para acessar valores pela chave passamos a chave dentro do []
print("Nome:", pessoa["nome"])
print("Idade:", pessoa["idade"])
print("Cidade:", pessoa["cidade"])

# Atribuir de uma nova chave depois q o dicionário foi instanciado apenas informamos a nova chave dentro de []
pessoa["sobrenome"] = "Andrade"
print("Sobrenome:", pessoa["sobrenome"])

# Atualizar um valor 
pessoa["idade"] = 31
print("Idade atualizada:", pessoa["idade"])

# Remover um par chave valor 
del pessoa["sobrenome"]
print("Dicionario atualizado: ", pessoa)

# keys() retorna todos as chaves do dicionário em formato de lista
chaves = pessoa.keys()
print("Chaves do dicionário:", chaves)

# para retornar uma chave especifica pelo índice não podemos acessar diretamente precisamos transformar em lista
chave_indice = list(pessoa.keys())
print("Índice 0 da chaves do dicionário:", chave_indice[0])

# values() retorna todos os valores do dicionário em formato de lista
valores = pessoa.values()
print("Valores do dicionário:", valores)

# para retornar um valor especifica pelo índice não podemos acessar diretamente precisamos transformar em lista
valor_indice = list(pessoa.values())
print("Índice 0 do valor do dicionário:", valor_indice[0])

# items() retorna todos os pares chave valor em formato de tupla
itens = pessoa.items()
print("Tupla com os pares chave valor do dicionário:", itens)

# para retornar uma chave especifica pelo índice não podemos acessar diretamente precisamos transformar em lista
# neste caso precisamos passar dois pares de [] tanto o indice da chave como o índice do valor
itens_indice = list(pessoa.items())
print("Índice 0 do par chaves valor do dicionário:%s = %s" % (itens_indice[0][0], itens_indice[0][1]))