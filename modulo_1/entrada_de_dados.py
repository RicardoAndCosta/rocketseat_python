# para capturarmos as entrada dos dados usamos o input()
# um ponto importante é que os dados recebidos pelo input() serão strings 

# input()
idade = int(input("Qual a sua idade? "))
if idade >= 18:
    print("Você é maior de idade")
elif idade >= 12:
    print("Você é adolescente")
else:
    print("Você é criança")

mensagem = "Pode tirar a cnh" if idade >= 18 else "Você não pode tirar a cnh"
print(mensagem)