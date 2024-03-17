# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]
# Embedded file name: data/data_utils.py
import string, random, re

def generate_password(len):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join((random.choice(characters) for i in range(len)))
    ch_special = False
    ch_digit = False
    ch_upper = False
    ch_lower = False
    password_arr = list(password)
    for index, item in enumerate(password_arr):
        if item in string.digits:
            ch_digit = True
        if item in string.punctuation:
            ch_special = True
        if item in string.ascii_lowercase:
            ch_lower = True
        if item in string.ascii_uppercase:
            ch_upper = True
        replacements = []

    if not ch_special:
        i = random.choice([x for x in range(len - 1) if x not in replacements])
        password_arr[i] = random.choice(string.punctuation)
        replacements.append(i)
    if not ch_digit:
        i = random.choice([x for x in range(len - 1) if x not in replacements])
        password_arr[i] = random.choice(string.digits)
        replacements.append(i)
    if not ch_lower:
        i = random.choice([x for x in range(len - 1) if x not in replacements])
        password_arr[i] = random.choice(string.ascii_lowercase)
        replacements.append(i)
    if not ch_upper:
        i = random.choice([x for x in range(len - 1) if x not in replacements])
        password_arr[i] = random.choice(string.ascii_uppercase)
        replacements.append(i)
    return "".join(password_arr)


def sanitize_username(user):
    username = user.username.lower()
    if len(username) > 9:
        username = username[0:9]
    username = re.sub("[^a-z0-9-]", "-", username)
    username = re.sub("^[^a-z0-9-]", "a", username)
    username = f"{username}-{user.user_id.hex[0:10]}"
    return username


def is_sanitized(v):
    if v:
        if isinstance(v, str):
            return v.count("*") == len(v.strip())
        return False

# okay decompiling ../bytecode/data/data_utils.pyc
