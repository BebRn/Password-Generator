import streamlit as st
import requests
from password_strength import PasswordStats
import time
import re

regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
def check(email):

    if(re.fullmatch(regex, email)):
        return True
 
    else:
        return False

# Function to send user credentials to API for sign up
def sign_up(email, password):
    login_url = f"http://localhost:8000/signup/?email={email}&password={password}"
    response = requests.post(login_url)
    if response.status_code == 200:
        st.success("Account created successfully. Please log in.")
    elif (response.status_code == 400):
        st.error("Account with this email already exists. Please log in.")
    else:
        st.error("Failed to create account. Please try again.")

# Function to send user credentials to API for log in
def log_in(email, password):
    login_url = f"http://localhost:8000/login?email={email}&password={password}"
    response = requests.post(login_url)
    if response.status_code == 200:
        login_response = response.json()
        access_token = login_response.get('access_token')
        if access_token:
            st.success(f"Welcome, {email}!")
            # Store access_token in SessionState
            st.session_state.access_token = access_token
            
            
        else:
            st.error("Access token not found in response.")
    else:
        st.error("Invalid email or password. Please try again.")

def login():
    st.title("Sign Up / Log In")

    # User action selection (sign up or log in)
    action = st.radio("Select Action", ("Sign Up", "Log In"))

    if action == "Sign Up":
        st.header("Sign Up")
        new_email = st.text_input("Enter Email:")
        new_password = st.text_input("Enter Password:", type='password')
        if st.button("Sign Up"):
            if check(new_email) == False:
                st.error("Invalid email")
            else:
                sign_up(new_email, new_password)

    elif action == "Log In":
        st.header("Log In")
        email = st.text_input("Email:")
        password = st.text_input("Password:", type='password')
        if st.button("Log In"):
            log_in(email, password)



# Function to send password generation request to API
def generate_password(length, include_uppercase, include_lowercase, include_digits, include_special, tag,custom_word):
    url = f"http://localhost:8000/generate-password/?token={st.session_state.access_token}&length={length}&custom_word={custom_word}&include_uppercase={include_uppercase}&include_lowercase={include_lowercase}&include_digits={include_digits}&include_special={include_special}&tag={tag}"
    response = requests.get(url)
    if response.status_code == 200:
        st.success("Password generated successfully:")
        data = response.json()
        password = data.get('password')
        tag = data.get('tag')
        st.write(f"# Tag: {tag}")
        st.write(f"## Password: {password}")

        stats = PasswordStats(password)
        strength_score = stats.strength()
        strength=""
        if strength_score < 0.2:
            strength="Very Weak"
        elif strength_score < 0.4:
            strength="Weak"
        elif strength_score < 0.6:
            strength="Moderate"
        elif strength_score < 0.8:
            strength="Strong"
        else:
            strength="Very Strong"
        st.write(f"## Strength: {strength}")


    else:
        st.error("Failed to generate password.")

def generate():
    st.title("Password Generator")

    if (('access_token' not in st.session_state) or (st.session_state.access_token is None)):
        st.error('Please login first')
    else:
        length = st.slider("Length", min_value=1, max_value=32, value=8)
        custom_word = st.text_input("Custom Word")
        include_uppercase = st.checkbox("Include Uppercase", value=True)
        include_lowercase = st.checkbox("Include Lowercase", value=True)
        include_digits = st.checkbox("Include Digits", value=True)
        include_special = st.checkbox("Include Special Characters", value=True)
        tag = st.text_input("Tag")

        if st.button("Generate Password"):
            generate_password(length, include_uppercase, include_lowercase, include_digits, include_special, tag, custom_word)



def viewpass():
    st.title("View Passwords")

    if (('access_token' not in st.session_state) or (st.session_state.access_token is None)):
        st.error('Please login first')
    else:
        url = f"http://localhost:8000/password-data/?token={st.session_state.access_token}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            passwords = data
            if passwords:
                st.write("## Passwords:")
                password_data = [{"Serial No.": i+1, "Tag": tag, "Password": password} for i, (tag, password) in enumerate(passwords.items())]
                table_style = """
                <style>
                    .dataframe tbody tr th {
                        text-align: center;
                        background-color: #f8f9fa !important;
                        color: #007bff !important;
                        font-size: 540px;
                    }
                    .dataframe tbody tr td {
                        text-align: center;
                        background-color: #ffffff !important;
                        color: #000000 !important;
                        font-size: 540px;
                    }
                    .dataframe thead th {
                        background-color: #007bff !important;
                        color: #ffffff !important;
                    }
                </style>
                """
               
                st.dataframe(password_data)
                st.markdown(f'<style>.dataframe {{ font-size: 600px; }}</style>', unsafe_allow_html=True)
            else:
                st.write("No passwords found.")
        else:
            st.error("Failed to fetch passwords.")


def logout():
    st.session_state.access_token = None
    st.success("Logged out successfully.")
    time.sleep(1)


def main():
 

    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ("Login", "Password Generator", "View Passwords"))

    if page == "Login":
        login()
    elif page == "Password Generator":
        generate()
    elif page == "View Passwords":
        viewpass()
    if st.sidebar.button("Logout"):
        logout()    
        st.rerun()


if __name__ == "__main__":
    main()
