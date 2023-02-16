import time
from tkinter import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import openssl
from tkinter import *


cipher = []
plain = []
alphabet = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z", " "]
def encrypt_cc(text,key):
    for x in range(0,len(text)):
        for a in alphabet:
            if text[x] == a:
                cipher.append(alphabet[(int(alphabet.index(a))+key)%27])
    cipher_text="".join(cipher)
    cipher.clear()
    return texts.insert(1.0,cipher_text.title())
def decrypt_cc(text,key):
    for x in range(0,len(text)):
        for a in alphabet:
            if text[x] == a:
                plain.append(alphabet[(int(alphabet.index(a))-key)%27])
    plain_text="".join(plain)
    plain.clear()
    return texts.insert(1.0,plain_text.title())



def home():
    global texts
    def pass_encrypt_ceser():
        plaintext= texts.get(1.0, "end").lower()
        keys = int(key.get(1.0, "end"))
        texts.delete(1.0, "end")
        encrypt_cc(plaintext,keys)
    def pass_decrypt_ceser():
        ciphertext= texts.get(1.0, "end").lower()
        keys = int(key.get(1.0, "end"))
        texts.delete(1.0, "end")
        decrypt_cc(ciphertext,keys)
    canver = Canvas(width=750, height=360)
    canver.place(x=-2, y=0)
    bg = canver.create_image(376, 180, image=background2)
    sideber2 = canver.create_image(30,120, image=sideber)
    box = canver.create_image(280, 140, image=text_box)
    sideblock = canver.create_image(620, 70, image=side_block)
    facebook = canver.create_image(620, 180, image=fb)
    instagram = canver.create_image(620, 230, image=ig)
    whatsapp = canver.create_image(620, 280, image=wa)

    #ec = canver.create_image(170,315, image=encoce)
    texts = Text(canver, bg="#594a59", height=14,fg="#ffffff", border=0, width=60, font=("arial", 10))
    texts.place(x=66, y=32)
    key = Text(canver, width=14,height=3, bg="#594a59", fg="#ffffff", border=0, font=("arail", 15))
    key.place(x=540,y=30)
    ec = Button(canver, image=encoce, border=0, bg="#A61E22",fg="#CC2345", command=pass_encrypt_ceser)
    ec.place(x=70, y=300)
    dc = Button(canver, image=decode, border=0, bg="#A61E22", fg="#CC2345", command=pass_decrypt_ceser)
    dc.place(x=350, y=300)
    key.insert(1.0, "insert key")
    #de = canver.create_image(370, 315, image=decode)
#TODO 1: the home gui page

def loading_page():
    def logo2():
        lg = canver.create_image(376,180, image=logo)
    canver = Canvas(width=750, height=360)
    canver.place(x=-2, y=0)
    bg = canver.create_image(376, 180, image=background)
    canver.after(1000, logo2)
    canver.after(2000, home)



#TODO 2: the loading page with the loge to wait for 3 secounds


def RSA():

    def encrypt_with_public_key(message):
        ciphertext = private_key.public_key().encrypt(message,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return ciphertext

    def decrypt_with_private_key(ciphertext):
        backend = openssl.backend
        # Load the private key
        private_key = serialization.load_pem_private_key(private_pem, password=None, backend=backend)

        # Decrypt the message
        plaintext = private_key.decrypt(ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return plaintext
    # Generate a private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Serialize the private key
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

    # Serialize the public key
    public_pem = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Encrypt a message
    text = input("enter")
    message = text.encode("utf-8")
    ec = encrypt_with_public_key(message)
    dc = decrypt_with_private_key(encrypt_with_public_key(message))

root = Tk()
root.geometry("750x360")
root.title("cryptography")
background = PhotoImage(file="image/background.png")
logo = PhotoImage(file="image/Asset 1.png")
background2 = PhotoImage(file="image/background_2.png")
sideber = PhotoImage(file="image/sidebar.png")
text_box = PhotoImage(file="image/Asset 22.png")
side_block = PhotoImage(file="image/side block.png")
ig = PhotoImage(file="image/ig.png")
wa = PhotoImage(file="image/wp_1.png")
fb = PhotoImage(file="image/fb.png")
encoce = PhotoImage(file="image/ENCRYPT.png")
decode = PhotoImage(file="image/DECRYPT.png")
loading_page()
root.mainloop()