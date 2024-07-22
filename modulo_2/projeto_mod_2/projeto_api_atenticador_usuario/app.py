from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt


app = Flask(__name__)
# Configuração necessária e obrigatória para acessar o bco de dados
# A primeira é uma chave secreta que será utilizada nos acessos ao db LER DOCUMENTAÇÃO SQLALCHEMY
app.config['SECRET_KEY'] = "your_secret_key"
# A segunda é o caminha para acessar o DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# optei por não alterar o bco de dados, durante o curso o bco é trocado pelo mysql usando docker, pois 
# tive problemas com os acessos adm na máquina e mesmo instalando o docker ao tentar criar o bco era 
# apresentado erro de criação/acesso ao bco, por esse motivo escolhi manter o sqlite para que fosse
# possível concluir o curso.

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
        
        if user and bcrypt.checkpw(str.encode(password), user.password):
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
      hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
      user = User(username=username, password=hashed_password, role='user')
      db.session.add(user)
      db.session.commit()

      return jsonify({"message": "Usuário cadastrado com sucesso!"})
  
  return jsonify({"message": "Dados invalidos"}), 400

@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return {"username": user.username}
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"message": "Operação não permitida"}), 403
    
    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()

        return jsonify ({"message": f"Usuário {id_user} atualizado com sucesso"})    
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if id_user == current_user.id or current_user.role != 'admin':
        return jsonify ({"message": "Deleção não permitida"}), 403
    
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} deletado com sucesso"})
    
    return jsonify({"message": "Usuário não encontrado"}), 404

if __name__ == '__main__':
    app.run(debug=True)