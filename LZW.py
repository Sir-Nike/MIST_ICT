def lzw_compress(uncompressed: bytes) -> list[int]:
    dict_size = 256
    dictionary = {bytes([i]): i for i in range(dict_size)}

    w = b""
    result = []
    for c in uncompressed:
        wc = w + bytes([c])
        if wc in dictionary:
            w = wc
        else:
            result.append(dictionary[w])
            dictionary[wc] = dict_size
            dict_size += 1
            w = bytes([c])
    
    if w:
        result.append(dictionary[w])
    return result

def lzw_decompress(compressed: list[int]) -> bytes:
    from io import BytesIO
    dict_size = 256
    dictionary = {i: bytes([i]) for i in range(dict_size)}
    result = BytesIO()
    w = bytes([compressed.pop(0)])
    result.write(w)

    for k in compressed:
        if k in dictionary:
            entry = dictionary[k]
        elif k == dict_size:
            entry = w + w[:1] # Special LZW case
        else:
            raise ValueError("Bad compressed k")
        
        result.write(entry)
        dictionary[dict_size] = w + entry[:1]
        dict_size += 1
        w = entry
    
    return result.getvalue()
