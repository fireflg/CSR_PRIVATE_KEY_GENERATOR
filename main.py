from OpenSSL import crypto
import os
import json
import sys


def json_parse_mkdir():
    f = open('config.json')
    x = json.load(f)
    f.close()
    return x


def generate_dirs_keys():
    data = json_parse_mkdir()
    for i in data:
        if os.path.exists(i['CN']):
            print('Папка с таким ключом уже существует')
            sys.exit(1)
        else:
            os.mkdir(i["CN"])
    for i in data:
        key = crypto.PKey()
        kept = os.path.join(os.getcwd(), i["CN"], f'{i["CN"]}.key')
        reqpt = os.path.join(os.getcwd(), i["CN"], f'{i["CN"]}.csr')
        if os.path.exists(kept):
            print(f'Ключ в этой папке уже существует, проверьте папку {os.path.join(os.getcwd(), i["CN"])}')
        else:
            print(f'Генирируем ключ для {i["CN"]}')
            key.generate_key(crypto.TYPE_RSA, 2048)
            f = open(kept, "wb")
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            f.close()

        if os.path.exists(reqpt):
            print(f'Файл запроса в этой папке уже существует, проверьте папку {os.path.join(os.getcwd(), i["CN"])}')
            sys.exit(1)
        else:
            print(f'Генирируем файл запроса для {i["CN"]}')
            req = crypto.X509Req()
            req.get_subject().CN = i["CN"]
            req.get_subject().OU = i["OU"]
            req.get_subject().O = i["O"]
            req.get_subject().emailAddress = i["E"]
            req.get_subject().L = i["L"]
            req.get_subject().C = i["C"]

            sans_list = []

            for san in i["SAN"]:
                sans_list.append("DNS: {0}".format(san))

            sans_list = ", ".join(sans_list).encode()

            x509_extensions = ([])

            if sans_list:
                x509_extensions.append(crypto.X509Extension("subjectAltName".encode(), False, sans_list))

            req.add_extensions(x509_extensions)
            req.set_pubkey(key)
            req.sign(key, "sha256")
            f = open(reqpt, "wb")
            f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
            f.close()


generate_dirs_keys()
