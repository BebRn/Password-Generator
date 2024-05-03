# trunk-ignore-all(black)
import jwt
from fastapi import APIRouter,Depends,HTTPException,status
from .. import models
from sqlalchemy.orm import Session
import os
from sqlalchemy import update
from .. database import get_db
from fastapi.responses import FileResponse
from passlib.context import CryptContext
from datetime import datetime, timedelta
from string import ascii_lowercase, ascii_uppercase, digits, punctuation
from random import choice
from fastapi.security import OAuth2PasswordBearer
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
router=APIRouter(
    prefix='',
    tags=['main']
)

key = b'oPdxRT3XMqt3htoOnNir89sdsB6VEMbm'

def encrypt_sp(name: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv=os.urandom(16))
    ct_bytes = cipher.encrypt(pad(name.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv + ':' + ct

def decrypt_sp(enc_name: str, key: bytes) -> str:
    iv, ct = enc_name.split(':')
    iv = b64decode(iv)
    ct = b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')




#password hashing object
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret key for signing JWT tokens
SECRET_KEY = "f23e80a8112ae307247f2ee925e12f37e84fd102e256386d4b2779ec465b927f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Generate JWT token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return True  # Token is valid
    except jwt.ExpiredSignatureError:
        # Token has expired
        return False
    except jwt.InvalidTokenError:
        # Token is invalid
        return False

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def generate_password(length: int, custom_word: str = '', 
                      include_uppercase: bool = True, include_lowercase: bool = True, 
                      include_digits: bool = True, include_special: bool = True):
    characters = ''
    if include_uppercase:
        characters += ascii_uppercase
    if include_lowercase:
        characters += ascii_lowercase
    if include_digits:
        characters += digits
    if include_special:
        characters += punctuation
    for char in custom_word:
        characters = characters.replace(char, '')

    password = ''
    if length <= len(custom_word):
        return custom_word[:length]
    else:
        remaining_length = length - len(custom_word)
        password += custom_word
        for i in range(remaining_length):
            password += choice(characters)
    return password[:length]

@router.post("/signup/")
def signup(email: str, password: str, db: Session = Depends(get_db)):
    if db.query(models.UserCredentials).filter(models.UserCredentials.email == email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    hashed_password = pwd_context.hash(password)
    new_user = models.UserCredentials(email=email, password=hashed_password)
    db.add(new_user)
    db.commit()
    return {"message": True}

@router.post("/login/")
def login(email: str, password: str, db: Session = Depends(get_db)):

    user = db.query(models.UserCredentials).filter(models.UserCredentials.email == email).first()
    if user is None or not pwd_context.verify(password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    return {"message": True,"access_token": access_token, "token_type": "bearer"}



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@router.get("/generate-password/")
def get_password(token: str = '', length: int = 8, custom_word: str = '', 
                 include_uppercase: bool = True, include_lowercase: bool = True, 
                 include_digits: bool = True, include_special: bool = True,tag: str = '',db: Session = Depends(get_db)):
    if not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    password = generate_password(length, custom_word, include_uppercase, include_lowercase, include_digits, include_special)
    e_password=encrypt_sp(str(password),key)
    email = decode_token(token)

    existing_password_data = db.query(models.PasswordData).filter(models.PasswordData.email == email).first()

    if existing_password_data:
        existing_tag_password = existing_password_data.tag_password
        #convert to normal json
        existing_tag_password[tag] = e_password
        # Update the tag_password attribute of the PasswordData instance
        existing_password_data.tag_password = existing_tag_password

        stmt = (
            update(models.PasswordData).
            where(models.PasswordData.email == email).  
            values(tag_password=existing_tag_password)        
        )
        db.execute(stmt)
        db.commit()
        return {"tag":tag,"password":password}
    # If there is no existing data, create a new entry
    new_password_data = models.PasswordData(email=email, tag_password={tag: e_password})
    db.add(new_password_data)
    db.commit()
    db.refresh(new_password_data)
    return {"tag":tag,"password":password}


@router.get("/password-data/")
def get_password_data(token: str, db: Session = Depends(get_db)):

    email = decode_token(token)

    password_data = db.query(models.PasswordData).filter(models.PasswordData.email == email).first()

    if not password_data:
        raise HTTPException(status_code=404, detail="No password data found for the user")
    data=password_data.tag_password
    for i in data:
        data[i]=decrypt_sp(data[i],key)
    return data
