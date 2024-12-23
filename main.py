import streamlit as st
import polars as pl

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode())).decode('ascii')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

encrypt = False
decrypt = False

col1, col2 = st.columns(2)

with col1:
    uploaded_file = st.file_uploader("Choose a file")

with col2:
    st.text_input("Key", key="key")

if uploaded_file is not None:
    data = pl.read_csv(uploaded_file)
    
    st.write(data)

    btn_col1, btn_col2 = st.columns(2)
    
    with btn_col1:
        if st.button(label='Encrypt', use_container_width=True):
            encrypt = True
            decrypt = False

    with btn_col2:
        if st.button(label='Decrypt', use_container_width=True):
            encrypt = False
            decrypt = True

    options = st.multiselect(
        "Columns",
        data.columns,
        data.columns,
    )

    if st.session_state.key and encrypt:
        
        encryption = AESCipher(st.session_state.key)
        
        encrypted = data.with_columns(
            pl.col(options).map_elements(lambda x: str(encryption.encrypt(str(x))), return_dtype=pl.String)
        )

        st.write("Encrypted Data:")

        encrypted

    if st.session_state.key and decrypt:
        
        encryption = AESCipher(st.session_state.key)
        
        decrypted = data.with_columns(
            pl.col(options).map_elements(lambda x: str(encryption.decrypt(str(x))), return_dtype=pl.String)
        )

        st.write("Decrypted Data:")

        decrypted