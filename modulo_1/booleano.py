# são retornos que podem ser utilizados nas condicionais onde determinamos se um bloco de código 
# será ou não utilizado, portanto, só podem ser retornar Verdadeiro ou Falso

# Verdadeiro
True

# Falso
False

# Condicionais
if True:
    print("Bloco IF vai ser executado, caso seja True")
else:
    print("Bloco ELSE será executado, caso seja False")

# Operadores lógicos, usamos nas condicionais caso precise de mais de uma validação 

# AND Todas as condições precisam ser verdadeiras para que seja executada a condição
if True and True:
    print("Bloco será executado")

if True and False:
    print("Bloco não será executado")

if False and False:
    print("Bloco não será executado")

# OR Apenas uma das condições precisa ser verdadeira para que condicional seja executada
if True or False:
    print("Bloco será executado")

if True or False:
    print("Bloco será executado")

if False and False:
    print("Bloco não será executado")