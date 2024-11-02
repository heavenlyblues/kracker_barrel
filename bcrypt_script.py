import bcrypt

password = b"loveme"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

with open("refs/password_to_crack", "wb") as file:
    file.write(hashed)

print(hashed)