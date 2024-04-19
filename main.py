import json


with open('cache.json', 'r') as file:
    data = json.load(file)


for each in data:
    vin = each.get('vin')
    if len(vin) == 1:
        print(len(vin))
        prevout = vin[0].get('prevout')
        if prevout.get('scriptpubkey_type') == 'p2pkh':
            print(prevout.get('scriptpubkey_asm'))
            print(prevout.get('scriptpubkey_type'))

    print(vin)
