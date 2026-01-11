import random
import os

filename = "layout.txt"
num_nodes = 50
max_x = 150
max_y = 150

with open(filename, "w") as f:
    for _ in range(num_nodes):
        x = random.randint(0, max_x)
        y = random.randint(0, max_y)
        f.write(f"{x} {y}\n")