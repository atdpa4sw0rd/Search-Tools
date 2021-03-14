import os,sys




def items_all():
    items = []
    with open("./temp/items",'r',encoding='utf8') as f:
        info = f.readlines()

    for i in info:
        items.append(i.strip())

    return items
