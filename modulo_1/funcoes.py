# Funções são blocos de códigos reutilizaveis e executam uma tarefa especifica qdo chamados
# e podem receber informações e retornar informações

# sempre usamos o DEF seguido do nome da função e () e dentro do () os paramentros finalizando com :
def saudacao(nome):
    print(f"Olá, {nome}!")

print("\nChamando a função saudacao:")
saudacao("Alice")
saudacao("Bob")

# Funcao com retorno
def quadrado(numero):
    resultado = numero ** 2
    return resultado
print("\nChamando função quadrado():")
resultado_quadrado = quadrado(5)
print("Resultado da função quadrado:", resultado_quadrado)

# Funçao com mais de um parametro
def soma(numero1, numero2):
    return numero1 + numero2
print("/nChamando a função soma:")
resultado_soma = soma(20, 50)
print("A soma do número 20 e numero 50 é:", resultado_soma)

# Função recebendo input() e retornando
def multiplicacao(numero1, numero2):
    return numero1 * numero2
print("\nChamando a função multiplicação")
numero1 = int(input("Informe o primeiro número: "))
numero2 = int(input("Informe o segundo número: "))
resultado_multiplicacao = multiplicacao(numero1, numero2)
print(f"\nA multiplicação de {numero1} por {numero2} é {resultado_multiplicacao}")