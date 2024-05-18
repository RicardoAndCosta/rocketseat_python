# São bibliotecas criadas por terceiros e não feitos pelo python
# Precisamos instalar elas pelo terminal para podermos utilizar pelo comando PIP INSTALL nome_do_modulo
# Para utilizar as bibliotecas devemos consultar toda a documentação e é importante sempre usar bibliotecas que a 
# comunidade recomenda

print("\nImportação e uso de um módulo de terceiros")
import requests

url = "https://www.example.com"
response = requests.get(url)
print(f"Solicitação HTTP para {url} retornou o status {response.status_code}")