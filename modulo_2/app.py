from flask import Flask

# __name__ == "__main__"
app = Flask(__name__)

# rotas são as formas que a api será acessada recebendo e retornando as requisições
@app.route("/")
def hello_worl():
    return "Hello world!"

@app.route("/about")
def about():
    return "Página sobre"


# Executa o programa de forma manual e usado apenas para o desenvolvimento local
if __name__ == "__main__":
    app.run(debug=True)