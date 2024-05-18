# Todo texto (String) em Python precisa estar entre aspas indiferente se são duplas "" ou simples '' 
# porém por boa prática seriam duplas. 
# Não precisamos de nenhuma configuração UFT-8 para acentuação ou caracteres especiais

# Declaração
nome_completo = "Ricardo Andrade"

# Possibilita pular linhas
nome_completo_aspas = """Ricardo
ANdrade"""

# Quebra de linha
nome_completo_quebra = "Ricardo \
    Andrade"

nome = "Ricardo"
sobrenome = "Andrade"

# Formatação
print("Nome completo (1ª forma):", nome_completo) 
print("Nome completo (2ª forma):" + nome_completo) # concatenação
print("Nome completo (3ª forma):" + "Ricardo" + "Andrade") # concatenar dentro do print
print("Nome completo (4ª forma):" + "Ricardo", "Andrade")
print("Nome completo (5ª forma):", nome_completo_aspas)
print("Nome completo (6ª forma):", nome_completo_quebra)
print("Nome completo (7ª forma): %s" % nome_completo) # tipo de substituição devemos usar o %s e depois um %
print("Nome completo (8ª forma): %s %s" % (nome, sobrenome)) # qdo tem duas variaveis precisa do () e , 
print(f"Nome completo (9ª forma): {nome} {sobrenome}") # necessario usar o f no inicio e as variaveis dentro {}
print("Nome completo (10ª forma): {} {}".format(nome, sobrenome)) 

# as Strings são uma listas de caracteres e podemos busca-las individualmente caso precise apenas passando 
# a posição que queremos retornar
nome[0] 

# Funções todas as funções da String podem ser utilizadas passando a variavel seguida de ponto e o metodo
nome.upper()

# upper() coloca toda a string em maiusculo
# lower() coloca toda a string em miniusculo
# count() conta quantas vezes o parametro ocorre dentro da string 
# find() ele busca na string se o parametro passado ocorre na string encontrando ele retorna a possição
# encode() / decode() codifica a string em bytes e vice-versa

# replace() substitui um caractere ou conjunto de caracteres por outro
nome.replace("Ri", "123") # substitui o primeiro parametro pelo segundo

# join() separa os caracteres da string pelo parametro passado
"-".join(nome)

# split() ele quebra a string em uma lista pelo passado
nome_completo.split(" ")

# starswith() começa com...dentro do () passa o parametro e retorna um boolean
# strip() remove um caractere especifico no inicio e no fim da string 
# rstrip() o mesmo que o anterior, mas remove apenas o caractere a direita
# lstrip() mesma coisa que o anterior, mas remove o caractere a esquerda

# in / not in, retorna um bolean se um parametro existe dentro da variavel 
"ar" in nome 