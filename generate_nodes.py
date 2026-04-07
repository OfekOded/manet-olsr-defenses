import random
import os

filename = "layout.txt"
num_nodes = 25
max_x = 10
max_y = 10

with open(filename, "w") as f:
    for _ in range(num_nodes):
        x = random.randint(0, max_x)
        y = random.randint(0, max_y)
        f.write(f"{x} {y}\n")