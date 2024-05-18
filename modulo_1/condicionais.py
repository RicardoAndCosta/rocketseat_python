# Condicionais permitem tomar decisões com base em uma condição possibilitando a execução de blocos de código
# Em Pyhton não usa abrir chaves ou colchetes como em outras linguagens 
# Apenas identando e como : após a condição representa o inicio do bloco

# IF
idade = 18
print("Exemplo de comando if")
if idade >= 18:
    print("Você é maior de idade")

if idade == 19:
    print("Você tem 19 anos")

if idade < 18:
    print("Você é menor de idade")

if idade != 10:
    print("Você não tem 10 anos")

# ELSE
# A condição entra no ELSE qdo o IF não é atendido 
idade = 19
print("Exemplo de comando else")
if idade >= 18:
    print("Você é maior de idade")
else:
    print("Você é menor de idade")

# ELIF
# É um meio termo entre o if/else é como um "então" possibilitando criar mais uma condição
idade = 17
print("Exemplo de comando elif")
if idade >= 18:
    print("Você é maior de idade")
elif idade >= 12:
    print("Você é adolescente")
else:
    print("Você é criança")

# pode ser feito em apenas uma linha passando todo o comando para uma variavel
mensagem = "Pode tirar a cnh" if idade >= 18 else "Você não pode tirar a cnh"
print(mensagem)
