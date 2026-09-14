
data = bytearray(500 * 1024 * 1024)
for i in range(0, len(data), 4096):  # touche chaque page pour forcer l'allocation physique
    data[i] = 1