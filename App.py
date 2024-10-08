import streamlit as st
import sqlite3
import bcrypt
from datetime import datetime, timedelta
from eth_account import Account
from web3 import Web3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
import time
from openai import OpenAI
from poe_api_wrapper import AsyncPoeApi
import asyncio
import requests
from g4f.api import run_api
import g4f

# Initialize database
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password TEXT, name TEXT, wallet_address TEXT, private_key TEXT)''')
conn.commit()
# Web3 setup for BSC Testnet
bsc_testnet = Web3(Web3.HTTPProvider('https://data-seed-prebsc-1-s1.binance.org:8545/'))
contract_address = '0x847EC4aBbd7123d5BfF3d12b52B04aF146d00159'
contract_abi = '''
[
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "spender",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "allowance",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "needed",
				"type": "uint256"
			}
		],
		"name": "ERC20InsufficientAllowance",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "sender",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "balance",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "needed",
				"type": "uint256"
			}
		],
		"name": "ERC20InsufficientBalance",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "approver",
				"type": "address"
			}
		],
		"name": "ERC20InvalidApprover",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "receiver",
				"type": "address"
			}
		],
		"name": "ERC20InvalidReceiver",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "sender",
				"type": "address"
			}
		],
		"name": "ERC20InvalidSender",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "spender",
				"type": "address"
			}
		],
		"name": "ERC20InvalidSpender",
		"type": "error"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "owner",
				"type": "address"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "spender",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "Approval",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "from",
				"type": "address"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "to",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "Transfer",
		"type": "event"
	},
	{
		"inputs": [],
		"name": "INITIAL_SUPPLY",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "owner",
				"type": "address"
			},
			{
				"internalType": "address",
				"name": "spender",
				"type": "address"
			}
		],
		"name": "allowance",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "spender",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "approve",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "account",
				"type": "address"
			}
		],
		"name": "balanceOf",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "decimals",
		"outputs": [
			{
				"internalType": "uint8",
				"name": "",
				"type": "uint8"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "name",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "symbol",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "totalSupply",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "to",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "transfer",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "from",
				"type": "address"
			},
			{
				"internalType": "address",
				"name": "to",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "transferFrom",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
'''


contract = bsc_testnet.eth.contract(address=contract_address, abi=contract_abi)

# Utility functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def add_user(username, password, name, wallet_address, private_key):
    hashed_password = hash_password(password)
    c.execute("INSERT INTO users (username, password, name, wallet_address, private_key) VALUES (?, ?, ?, ?, ?)", 
              (username, hashed_password, name, wallet_address, private_key))
    conn.commit()

def get_user(username):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    return c.fetchone()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_data).decode('utf-8')

def decrypt(encrypted_data, password):
    decoded_data = base64.b64decode(encrypted_data.encode('utf-8'))
    salt, iv, ciphertext = decoded_data[:16], decoded_data[16:32], decoded_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def create_wallet():
    account = Account.create()
    private_key = account.key.hex()
    address = account.address

    # Use a default password for encryption
    default_password = "Fu9l3i$o=rljos?A*$5u"  # Replace with your actual default password
    encrypted_private_key = encrypt(private_key.encode('utf-8'), default_password)
    
    with open('encrypted_private_key.txt', 'w') as f:
        f.write(encrypted_private_key)
    st.success("Wallet created and private key encrypted successfully!")
    
    return private_key, address

def transfer_studycoin(to_address, amount):
    nonce = bsc_testnet.eth.get_transaction_count(owner_address)
    txn = contract.functions.transfer(to_address, amount).buildTransaction({
        'chainId': 97,
        'gas': 200000,
        'gasPrice': bsc_testnet.toWei('20', 'gwei'),
        'nonce': nonce
    })
    signed_txn = bsc_testnet.eth.account.signTransaction(txn, private_key=owner_private_key)
    txn_hash = bsc_testnet.eth.sendRawTransaction(signed_txn.rawTransaction)
    return bsc_testnet.toHex(txn_hash)


def display_chatbot():
    st.title("Study Assistant Chatbot")
    st.write("Your study assistant bot is here to help you!")

    assistant_prompt = "You are a study assistant bot designed to help with academic needs."

    # User input
    user_input = st.text_input("Ask a question:", "")

    if st.button("Submit"):
        if user_input:
            # Prepare the conversation messages
            messages = [
                {"role": "system", "content": assistant_prompt},
                {"role": "user", "content": user_input}
            ]

            try:
                # Use g4f.client to generate the response
                response = g4f.ChatCompletion.create(
                    model="gpt-4o",
                    messages=messages,
                    stream=False  # Set to False for non-streaming example
                )

                # Handle response as a dictionary
                if isinstance(response, dict) and 'choices' in response:
                    # Extract just the content of the assistant's reply
                    assistant_reply = response['choices'][0]['message']['content']
                else:
                    assistant_reply = "Sorry, I didn't understand the response format."

                # Display the assistant's response
                st.write("Response from the assistant:")
                st.write(assistant_reply)

            except Exception as e:
                st.error(f"Error while contacting API: {e}")

                
# Login functionality
def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Submit Login", key="submit_login"):
        user = get_user(username)  # Replace with your actual function to get user
        if user and check_password(password, user[1]):  # Replace with password checking logic
            st.success(f"Logged in as {user[2]}")
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.wallet_address = user[3]
            st.session_state.private_key = user[4]
            st.session_state.start_time = datetime.now()
            st.rerun()
            return True
        else:
            st.error("Invalid username or password")
    return False

# Signup functionality
def signup():
    st.subheader("Sign Up")
    new_username = st.text_input("New Username", key="signup_username")
    new_password = st.text_input("New Password", type="password", key="signup_password")
    name = st.text_input("Your Name", key="signup_name")
    if st.button("Submit Signup", key="submit_signup"):
        if get_user(new_username):  # Check if username exists
            st.error("Username already exists")
        else:
            private_key, wallet_address = create_wallet()  # Add wallet creation logic
            add_user(new_username, new_password, name, wallet_address, private_key)  # Add user logic
            st.success("Account created successfully. Please login.")
            st.write(f"Your new wallet address is: {wallet_address}")
            st.write(f"Private Key: {private_key}")

# Sidebar to display time left until coin release
def show_sidebar_time():
    if 'start_time' in st.session_state:
        time_spent = datetime.now() - st.session_state.start_time
        minutes_spent = time_spent.seconds // 60
        minutes_left = max(30 - minutes_spent, 0)
        st.sidebar.write(f"Time left until next coin reward: {minutes_left} minutes")

        if minutes_spent >= 30:
            st.sidebar.success("You've earned 10 StudyCoins!")
            if st.session_state.logged_in:
                transfer_studycoin(st.session_state.wallet_address, 10)  # Replace with actual transfer logic
                st.session_state.start_time = datetime.now()  # Reset timer after transfer
    else:
        st.sidebar.write("Start studying to earn StudyCoins!")

def main():
    # Initialize session state variables if they don't exist
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = ""
    if 'show_login' not in st.session_state:
        st.session_state.show_login = False
    if 'show_signup' not in st.session_state:
        st.session_state.show_signup = False

    # Persistent "Study Plus" title at the top
    st.markdown("<h1 style='text-align: center;'>Study Plus - The better way to study</h1>", unsafe_allow_html=True)

    # Show sidebar time tracker for coin release
    show_sidebar_time()

    # Show Login and Signup forms side by side if not logged in
    if not st.session_state.logged_in:
        col1, col2 = st.columns(2)

        with col1:
            if st.button("Login", key="login_button"):
                st.session_state.show_login = True
                st.session_state.show_signup = False  # Hide signup form if login is clicked

        with col2:
            if st.button("Sign Up", key="signup_button"):
                st.session_state.show_signup = True
                st.session_state.show_login = False  # Hide login form if signup is clicked

        # Display login form if "Login" button is clicked
        if st.session_state.show_login:
            login()

        # Display signup form if "Sign Up" button is clicked
        if st.session_state.show_signup:
            signup()

    # After logging in, show the chatbot and StudyCoin functionality
    if st.session_state.logged_in:
        
        st.write(f"Welcome, {st.session_state.username}!")  # Greet the user
        display_chatbot()  # Show chatbot


# Run the main function
if __name__ == '__main__':
    main()
