#!/usr/bin/python

# suporte LDAP
import ldap

# tratamento de arquivos: passwd, group e shadow
import pwd
import grp
import spwd

# funcoes de SO
import os

# tenta fechar a conexao com o servidor AD
try:
    l = ldap.initialize("ldap://IP.SERV.AD.DC/")
    username = "LEITORLDAP@DOMINIO.LOCAL"
    password = "SENHA"
    l.protocol_version = 3
    l.set_option(ldap.OPT_REFERRALS, 0)
    l.simple_bind_s(username, password)
except ldap.LDAPError, e:
    print e

# dominio base
baseDN = "DC=DOMINIO,DC=LOCAL"
searchScope = ldap.SCOPE_SUBTREE

# atributos de interesse
retrieveAttributes = ["msSFU30Name", "unixUserPassword", "uidNumber", "gidNumber", "unixHomeDirectory", "loginShell"]
searchFilter = "(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=*))"

# inicializa lista onde vamos salvar as contas
result_set = []

try:
    ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
    while 1:
        result_type, result_data = l.result(ldap_result_id, 0)
        if (result_data == []):
            break
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                                entrada = {}
                                if 'uidNumber' in result_data[0][1]:
                                        entrada['login'] = result_data[0][1]['msSFU30Name'][0]
                                        entrada['senha'] = result_data[0][1]['unixUserPassword'][0]
                                        entrada['uid'] = result_data[0][1]['uidNumber'][0]
                                        entrada['gid'] = result_data[0][1]['gidNumber'][0]
                                        entrada['home'] = result_data[0][1]['unixHomeDirectory'][0]
                                        entrada['shell'] = result_data[0][1]['loginShell'][0]
                                        result_set.append(entrada)
except ldap.LDAPError, e:
        print e

nome = []
for linha in open('/etc/postfix/nomes-completos'):
    nome.append(tuple(linha.strip().split(',')))
nome = dict(nome)

for usuario in result_set:
        try:
                grp.getgrgid(usuario['gid'])
        except KeyError:
                print "ERRO: tentando atribuir grupo nao-existente (" + usuario['gid'] + ") ao usuario " + usuario['login']
                continue

        try:
                pwd.getpwnam(usuario['login'])
        except KeyError:
                try:
                        pwd.getpwuid(int(usuario['uid']))
                        print "ERRO: tentando atribuir ID ja existente (" + usuario['uid'] + ") ao usuario " + usuario['login']
                        continue
                except KeyError:
                        if usuario['login'] in nome:
                                os.system("/usr/sbin/useradd -p '" + usuario['senha'] + "' -u " + usuario['uid'] +
                                                " -g " + usuario['gid'] + " -d " + usuario['home'] + " -m " +
                                                " -c " + "'" + nome[usuario['login']] + "'" +
                                                " -s " + usuario['shell'] + " " + usuario['login'])
                        else:
                                os.system("/usr/sbin/useradd -p '" + usuario['senha'] + "' -u " + usuario['uid'] + " -g " + usuario['gid'] + " -d " + usuario['home'] + " -m " + " -s " + usuario['shell'] + " " + usuario['login'])
                        os.system("/usr/sbin/zarafa-admin -u " + usuario['login'] +
                                  " --enable-feature imap --qs 0 --qw 0 --qh 0 1>/dev/null 2>&1")
                        continue

        senha_atual = spwd.getspnam(usuario['login'])
        if usuario['senha'] != spwd.getspnam(usuario['login']).sp_pwd:
                os.system("/usr/sbin/usermod -p '" + usuario['senha'] + "' " + usuario['login'])