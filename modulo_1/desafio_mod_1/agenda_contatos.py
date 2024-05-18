# Nesse desafio desenvolveremos uma agenda para salvar, editar, deletar e marcar um contato como favorito. 
# O resultado da aplicação deve ser apresentado no terminal. 
def adicionar_contato(agenda_contatos, nome_contato, telefone_contato, email_contato):
    agenda_contato = {"nome": nome_contato, "telefone": telefone_contato, "email": email_contato, "favorito": False}
    agenda_contatos.append(agenda_contato)
    print(f"{nome_contato} foi adicionado com sucesso!")
    return

def ver_contatos(agenda_contatos):
    print("\nContatos da Agenda:")
    for indice, agenda_contato in enumerate(agenda_contatos, start=1):
        status = "✓" if agenda_contato["favorito"] else " "
        nome_contato = agenda_contato["nome"]
        print(f"{indice}. [{status}] {nome_contato}")
    return

def ver_contato_detalhado(agenda_contatos, indice_contato):
    indice_contato_ajustado = int(indice_contato) - 1
    if indice_contato_ajustado >= 0 and indice_contato_ajustado < len(agenda_contatos):
        nome_contato = agenda_contatos[indice_contato_ajustado]["nome"]
        telefone_contato = agenda_contatos[indice_contato_ajustado]["telefone"]
        email_contato = agenda_contatos[indice_contato_ajustado]["email"]
        status = "✓" if agenda_contatos[indice_contato_ajustado]["favorito"] else " "
        print("Favorito: ", status)
        print("Nome: ", nome_contato)
        print("Telefone: ", telefone_contato)
        print("E-mail: ", email_contato)
    else: 
        print("Índice de contato inválido!")
    return

def atualizar_contato(agenda_contatos, indice_contato, novo_nome_contato, novo_telefone_contato, novo_email_contato):
    indice_contato_ajustado = int(indice_contato) - 1
    if indice_contato_ajustado >= 0 and indice_contato_ajustado < len(agenda_contatos):
        agenda_contatos[indice_contato_ajustado]["nome"] = novo_nome_contato
        agenda_contatos[indice_contato_ajustado]["telefone"] = novo_telefone_contato
        agenda_contatos[indice_contato_ajustado]["email"] = novo_email_contato
        print("Contato atualizado com sucesso!")
    else:
        print("Índice inválido!")
    return

def favoritar_contato(agenda_contatos, indice_contato):
    indice_contato_ajustado = int(indice_contato) - 1
    if indice_contato_ajustado >= 0 and indice_contato_ajustado < len(agenda_contatos):
        agenda_contatos[indice_contato_ajustado]["favorito"] = True
        print("Contato favoritado com sucesso!")
    else:
        print("Índice de tarefa inválido")
    return

def ver_contatos_favoritos(agenda_contatos):
    print("\nContatos Favoritos da Agenda:")
    for indice, agenda_contato in enumerate(agenda_contatos, start=1):
        if agenda_contato["favorito"]: 
            status = "✓"
            nome_contato = agenda_contato["nome"]
            print(f"{indice}.[{status}] {nome_contato}")
        else: 
            print("Não há contatos marcados como favoritos")
    return

def deletar_contato(agenda_contatos, indice_contato):
    indice_contato_ajustado = int(indice_contato) - 1
    if indice_contato_ajustado >= 0 and indice_contato_ajustado < len(agenda_contatos):
        del agenda_contatos[indice_contato_ajustado]
        print("Contato apagado com sucesso!")
    else:
        print("Índice de tarefa inválido")
    return


agenda_contatos = []
while True:
    print("\nMenu agenda de contatos:")
    print("1. Adicionar contato")
    print("2. Visualizar contatos")
    print("3. Visualizar detalhes do contato")
    print("4. Atualizar contatos")
    print("5. Favoritar contatos")
    print("6. Visualizar contatos favoritos")
    print("7. Apagar contato")
    print("8. Sair")

    escolha = input("Digite uma opção: ")

    if escolha == "1":
        nome_contato = input("Digite o nome do contato que deseja adicionar: ")
        telefone_contato = input("Digite o número do telefone do novo contato: ")
        email_contato = input("Digite o e-mail do novo contato: ")
        adicionar_contato(agenda_contatos, nome_contato, telefone_contato, email_contato)

    elif escolha == "2":
        ver_contatos(agenda_contatos) 

    elif escolha == "3":
        ver_contatos(agenda_contatos)
        indice_contato = input("Digite o número do contato que deseja mais detalhes: ")
        ver_contato_detalhado(agenda_contatos, indice_contato)

    elif escolha == "4":
        ver_contatos(agenda_contatos)
        indice_contato = input("Digite o número do contato que deseja atualizar: ")
        novo_nome_contato = input("Digite o nome: ")
        novo_telefone_contato = input("Digite o número do telefone atualizado: ")
        novo_email_contato = input("Digite o e-mail atualizado: ")
        atualizar_contato(agenda_contatos, indice_contato, novo_nome_contato, novo_telefone_contato, novo_email_contato)

    elif escolha == "5":
        ver_contatos(agenda_contatos)
        indice_contato = input("Digite o índice do contato que deseja favoritar: ")
        favoritar_contato(agenda_contatos, indice_contato)

    elif escolha == "6":
        ver_contatos_favoritos(agenda_contatos)

    elif escolha == "7":
        ver_contatos(agenda_contatos)
        indice_contato = input("Selecione o contato que será apagado: ")
        deletar_contato(agenda_contatos, indice_contato)

    elif escolha == "8":
        break

print("Programa finalizado")