import streamlit as st
import json
import os
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
from base64 import urlsafe_b64encode

# File paths
DATA_FILE = "data.json"
USER_FILE = "users.json"
LOCKOUT_FILE = "lockout.json"

# Load or initialize files
def load_data(file, default={}):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return default

def save_data(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# Load stored data
users = load_data(USER_FILE)
data_store = load_data(DATA_FILE)
lockouts = load_data(LOCKOUT_FILE)

# Generate key per session
if "fernet_key" not in st.session_state:
    key = urlsafe_b64encode(pbkdf2_hmac("sha256", b"some_secret", b"salt", 100000, dklen=32))
    st.session_state.fernet_key = key

cipher = Fernet(st.session_state.fernet_key)

# Helper functions
def hash_passkey(passkey, salt=b"salt"):
    return pbkdf2_hmac("sha256", passkey.encode(), salt, 100000).hex()

def is_locked(username):
    if username in lockouts:
        if time.time() < lockouts[username]["unlock_time"]:
            return True, int(lockouts[username]["unlock_time"] - time.time())
    return False, 0

def handle_failed_attempt(username):
    if username not in lockouts:
        lockouts[username] = {"count": 1, "unlock_time": 0}
    else:
        lockouts[username]["count"] += 1
        if lockouts[username]["count"] >= 3:
            lockouts[username]["unlock_time"] = time.time() + 60  # 1-minute lockout
            lockouts[username]["count"] = 0
    save_data(LOCKOUT_FILE, lockouts)

# Custom CSS
st.markdown("""
    <style>
        .main {
            background-color: #f4f4f4;
        }
        .stButton > button {
            background-color: #000000;
            color: white;
            border-radius: 5px;
        }
        .stTextInput, .stTextArea {
            border-radius: 5px;
        }
        .sidebar .sidebar-content {
            background-color: #ffffff;
        }
        h1, h2, h3 {
            color: #333333;
        }
    </style>
""", unsafe_allow_html=True)

# Sidebar Logo and Menu
st.sidebar.image("https://datavault.com.pk/wp-content/uploads/2024/11/data-vault-black-text.png", use_container_width=True)
menu = ["Register", "Login", "Store Data", "Retrieve Data", "About"]
choice = st.sidebar.selectbox("Navigation", menu)

# Pages
if choice == "Register":
    st.subheader("📝 Register New User")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")

    if st.button("Register"):
        if new_user and new_pass:
            if new_user in users:
                st.error("⚠️ Username already exists!")
            else:
                users[new_user] = hash_passkey(new_pass)
                save_data(USER_FILE, users)
                st.success("✅ User registered successfully!")
        else:
            st.error("All fields required.")

elif choice == "Login":
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        locked, seconds_left = is_locked(username)
        if locked:
            st.error(f"⏳ Account locked. Try again in {seconds_left} seconds.")
        elif username in users and users[username] == hash_passkey(password):
            st.session_state["user"] = username
            st.success(f"✅ Welcome, {username}!")
        else:
            handle_failed_attempt(username)
            st.error("❌ Invalid credentials.")

elif choice == "Store Data":
    if "user" not in st.session_state:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        user_input = st.text_area("Enter data to store:")
        passkey = st.text_input("Encryption Key (only you should know it):", type="password")

        if st.button("Encrypt & Save"):
            if user_input and passkey:
                enc = cipher.encrypt(user_input.encode()).decode()
                user_data = data_store.get(st.session_state["user"], [])
                user_data.append({"data": enc, "passkey": hash_passkey(passkey)})
                data_store[st.session_state["user"]] = user_data
                save_data(DATA_FILE, data_store)
                st.success("✅ Data stored securely!")
            else:
                st.error("Please enter both fields.")

elif choice == "Retrieve Data":
    if "user" not in st.session_state:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("🔍 Retrieve Your Data")
        user_data = data_store.get(st.session_state["user"], [])

        if not user_data:
            st.info("You have no stored data.")
        else:
            index = st.selectbox("Select Data Entry", range(len(user_data)))
            passkey = st.text_input("Enter your decryption key:", type="password")

            if st.button("Decrypt"):
                if passkey:
                    stored_entry = user_data[index]
                    if hash_passkey(passkey) == stored_entry["passkey"]:
                        decrypted = cipher.decrypt(stored_entry["data"].encode()).decode()
                        st.success(f"🔓 Decrypted Data: {decrypted}")
                    else:
                        st.error("❌ Wrong decryption key!")
                else:
                    st.error("Enter the key.")

elif choice == "About":
    st.title("📄 About Secure Data Vault")
    st.markdown("""
    Welcome to **Secure Data Vault**!  
    This application allows users to **securely store and retrieve sensitive information** with encryption.

    **🔐 Features:**
    - User registration and authentication
    - Lockout after failed login attempts
    - Data encryption using Fernet
    - Personal decryption keys for extra security

    **🛡️ Your data privacy is our priority.**

    Developed by Arisha.
    """)