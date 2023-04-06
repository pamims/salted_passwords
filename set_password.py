import os
import hashlib
import configparser

# get the raw text from the user
raw_password = input("Enter Password: ")

# turn the password into a series of bytes
encoded_password = raw_password.encode('utf-8')
# get some random bytes to salt the password
salt = os.urandom(16)
# get a hash of the password
hash_object = hashlib.sha256(encoded_password + salt)

# get the hash and the salt as strings to store
hash_string = hash_object.hexdigest()
salt_string = salt.hex()

# destroy old config file if it exists
config_path = "password_hash.config"

if os.path.exists(config_path):
    os.remove(config_path)
    print(f"old {config_path} removed")

# make a config object
config = configparser.ConfigParser()
config["password_data"] = {
    "SALT": salt_string,
    "HASH": hash_string
}

# store the data to config file
config_file = open(config_path, 'w')
config.write(config_file)
config_file.close()

print(f"new {config_file} saved")
