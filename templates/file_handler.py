import os
import encrypter


class File:
    def __init__(self, name, path, encryption_method=None):
        self.name = name
        self.path = path
        self.encryption_method = encryption_method
        self.directory = {
            "name": self.name,
            "path": self.path,
            "encryption_method": self.encryption_method
        }

    def encrypt(self, key):
        encrypter.encrypt_AesCrypt(self, key)

    def decrypt(self, key):
        encrypter.dencrypt_AesCrypt(self, key)

    def remove(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def save_obj(self):
        pass


def new_dir(dir_name):
    path = "files/" + str(dir_name)
    try:
        os.makedirs(path)
    except FileExistsError:
        # directory already exists
        pass


def files_in_dir(path):
    return [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
