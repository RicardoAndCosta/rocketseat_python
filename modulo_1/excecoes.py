# Exceções são erros que podem ocorrer em nosso sistema que podem prejudicar o funcionamento deles
# Em Pyhton utilizamos o Try/except

print("Exemplo de captura de excções")

# TRY - Tente excecutar 
try:
    numero = int(input("digite um número inteiro: "))
    resultado = 10 / numero

# EXCEPT - Se não conseguir capture o erro e realize uma tratativa sem interromper o programa
# EXCEPTION é uma captura generica podemos capturar mais exceções
except ValueError as e:
    print(f"Erro de value erro: {e}")

    # RAISE é uma forma proposital de interromper o programa
    raise ValueError("Tipo de variaveis incompativeis")
except Exception as e:
    print(f"Erro: {e}")

# neste caso o else só será executado se o programa não entrar em nenhuma exceção
else:
    print(f"Resultado: {resultado}")

# FINALLY independentemente se deu certo ou não o finally sempre será executado
finally:
    print("Operação finalizada")