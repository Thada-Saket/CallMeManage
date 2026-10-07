import secrets
import string

def rand_passwd():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = "".join(secrets.choice(alphabet) for _ in range(64))
    return password