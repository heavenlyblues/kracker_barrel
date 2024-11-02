import bcrypt

cheap_salt = bcrypt.gensalt(rounds=8)

password = b"nopassword"
hashed = bcrypt.hashpw(password, cheap_salt)

with open("refs/password_to_crack", "wb") as file:
    file.write(hashed)

print(hashed)