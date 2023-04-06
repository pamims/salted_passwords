import hashlib
import configparser
import os

config_path = "password_hash.config"

if not os.path.exists(config_path):
    print("No password is set")
    exit()

# get the config data from file
config = configparser.ConfigParser()
config.read(config_path)
salt_string = config["password_data"]["SALT"]
# turn the salt string into bytes
salt = bytes.fromhex(salt_string)
correct_hash_string = config["password_data"]["HASH"]

while True:
    encoded_password = input("Enter Password: ").encode('utf-8')
    hash_string = hashlib.sha256(encoded_password + salt).hexdigest()
    if hash_string == correct_hash_string:
        print("You know the password!")
        exit()
    else:
        print("This is not the correct password :(\n")
        continue
