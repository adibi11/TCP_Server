import os

with open("test.bin", "wb") as file:
    file.write(os.urandom(100 * 1024))
