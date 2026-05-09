name = "Edmar"
role = "admin"

print(f"Welcome {name}, you are logged in as {role}")
# Welcome Edmar, you are logged in as admin


class User:
    def __init__(self, name, role):
        self.name = name
        self.role = role

    def greet(self):
        return f"Hello, I am {self.name}"

# Creating an object
user1 = User("Edmar", "admin")
print(user1.greet())   # Hello, I am Edmar
print(user1.role)      # admin