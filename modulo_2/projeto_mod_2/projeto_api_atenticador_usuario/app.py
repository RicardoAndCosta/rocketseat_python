from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required


app = Flask(__name__)
# Configuração necessária e obrigatória para acessar o bco de dados
# A primeira é uma chave secreta que será utilizada nos acessos ao db LER DOCUMENTAÇÃO SQLALCHEMY
app.config['SECRET_KEY'] = "your_secret_key"
# A segunda é o caminha para acessar o DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# View Login
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        #print ({"username": username, "password": password}) # Se retirar o # e executar o comando é retornado as informações do usuário
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Acesso autorizado!"})
        
    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
   logout_user()
   return jsonify({"message": "Logout realizado com sucesso!"}) 

@app.route('/user', methods=['POST'])
def create_user():
  data = request.json
  username = data.get("username")
  password = data.get("password")

  if username and password:
      user = User(username=username, password=password)
      db.session.add(user)
      db.session.commit()

      return jsonify({"message": "Usuário cadastrado com sucesso!"})
  
  return jsonify({"message": "Dados invalidos"}), 400


@app.route("/hello-world", methods=["GET"])
def hello_world():
    return "Hello World"

if __name__ == '__main__':
    app.run(debug=True)