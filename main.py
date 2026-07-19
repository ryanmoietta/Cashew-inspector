#!/usr/bin/env python3

import sys
import re
import requests
import tldextract

from urllib.parse import urlparse, urljoin
from colorama import Fore, init


init(autoreset=True)


BANNER = r"""

  ___   __   ____  _  _  ____  _  _    __  __ _  ____  ____  ____  ___  ____  __  ____ 
 / __) / _\ / ___)/ )( \(  __)/ )( \  (  )(  ( \/ ___)(  _ \(  __)/ __)(_  _)/  \(  _ \
( (__ /    \\___ \) __ ( ) _) \ /\ /   )( /    /\___ \ ) __/ ) _)( (__   )( (  O ))   /
 \___)\_/\_/(____/\_)(_/(____)(_/\_)  (__)\_)__)(____/(__)  (____)\___) (__) \__/(__\_)

        Cashew Link Inspection
        Advanced URL Security Analyzer
"""

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "goo.gl",
    "cutt.ly",
    "ow.ly",
    "buff.ly"
}


KNOWN_BRANDS = {
    "google.com": "google",
    "youtube.com": "youtube",
    "paypal.com": "paypal",
    "apple.com": "apple",
    "microsoft.com": "microsoft",
    "amazon.com": "amazon",
    "facebook.com": "facebook",
    "instagram.com": "instagram"
}


SUSPICIOUS_PATHS = [
    "login",
    "signin",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "update",
    "confirm"
]


TYPO_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t"
}


def normalize(url):

    if not url.startswith(("http://", "https://")):
        return "http://" + url

    return url



# -----------------------------------
# Detect @ spoofing BEFORE url parsing
# -----------------------------------

def detect_at_trick(url):

    if "@" not in url:
        return None, None


    left, right = url.rsplit("@", 1)


    fake = left.split("://")[-1]

    real = right.split("/")[0]


    clean = "http://" + right


    return fake, clean



# -----------------------------------
# Get hostname safely
# -----------------------------------

def get_host(url):

    try:

        return (
            urlparse(url)
            .hostname
            .lower()
            .strip(".")
        )

    except:

        return ""



# -----------------------------------
# Redirect expansion
# -----------------------------------

def follow_redirects(url):

    chain = [url]


    try:

        session = requests.Session()


        session.headers.update({

            "User-Agent":
            "Mozilla/5.0 CashewSecurityScanner"

        })


        current = url


        for _ in range(10):

            response = session.get(
                current,
                allow_redirects=False,
                timeout=8
            )


            location = response.headers.get(
                "Location"
            )


            if not location:
                break


            current = urljoin(
                current,
                location
            )


            chain.append(current)



        return chain


    except:

        return chain



# -----------------------------------
# Shortener detection
# -----------------------------------

def is_shortener(host):

    return any(
        host == x or host.endswith("." + x)
        for x in SHORTENERS
    )



# -----------------------------------
# Brand impersonation
# -----------------------------------

def check_brand(host):

    score = 0
    alerts = []


    extracted = tldextract.extract(host)


    domain = extracted.domain.lower()

    suffix = extracted.suffix.lower()


    full = domain + "." + suffix



    # Real domains are safe

    if full in KNOWN_BRANDS:

        return score, alerts



    for brand_domain, brand in KNOWN_BRANDS.items():

        brand_name = brand.replace(
            "-",
            ""
        )


        if brand_name in domain:

            score += 35

            alerts.append(
                f"Possible {brand} impersonation"
            )


    return score, alerts



# -----------------------------------
# Typo / lookalike detection
# -----------------------------------

def check_typos(host):

    score = 0
    alerts = []


    converted = host.lower()


    for a,b in TYPO_MAP.items():

        converted = converted.replace(
            a,
            b
        )


    for brand in KNOWN_BRANDS.values():

        if brand in converted and brand not in host.lower():

            score += 40

            alerts.append(
                f"Possible fake spelling of {brand}"
            )


    return score, alerts



# -----------------------------------
# Main analysis
# -----------------------------------

def analyze(url):

    score = 0
    alerts = []


    original = normalize(url)


    fake_display, cleaned = detect_at_trick(original)



    if fake_display:


        score += 50


        alerts.append(
            "CRITICAL: @ symbol hides real destination"
        )


        alerts.append(
            "Fake displayed section: "
            + fake_display
        )


        analysis_url = cleaned


    else:

        analysis_url = original



    host = get_host(analysis_url)



    # Expand redirects

    chain = follow_redirects(
        analysis_url
    )


    final_url = chain[-1]

    final_host = get_host(
        final_url
    )



    if len(chain) > 1:

        alerts.append(
            "Redirect chain detected"
        )

        score += 10



    # Shortener

    if is_shortener(host):

        alerts.append(
            "URL shortener detected"
        )

        score += 20



    # Punycode

    if "xn--" in final_host:

        alerts.append(
            "Punycode detected"
        )

        score += 40



    # IP address

    if re.match(
        r"^\d+\.\d+\.\d+\.\d+$",
        final_host
    ):

        alerts.append(
            "Destination is an IP address"
        )

        score += 30



    # Brands

    s,a = check_brand(final_host)

    score += s

    alerts.extend(a)



    # Typos

    s,a = check_typos(final_host)

    score += s

    alerts.extend(a)



    # Paths

    path = urlparse(
        final_url
    ).path.lower()



    for word in SUSPICIOUS_PATHS:

        if word in path:

            score += 10

            alerts.append(
                "Suspicious path keyword: "
                + word
            )



    return {

        "score": min(score,100),

        "original": original,

        "domain": final_host,

        "destination": final_url,

        "chain": chain,

        "alerts": list(set(alerts))

    }



# -----------------------------------
# Output
# -----------------------------------

def report(url):

    result = analyze(url)


    print("\n" + "="*75)

    print(
        "CASHEW LINK INSPECTION REPORT".center(75)
    )

    print("="*75)



    print("\nOriginal:")
    print(result["original"])


    print("\nFinal Destination:")
    print(result["destination"])


    print("\nFinal Domain:")
    print(result["domain"])



    print("\nRedirect Chain:")

    for item in result["chain"]:

        print(
            " ->",
            item
        )



    score = result["score"]


    print("\nRisk Score:")


    if score >= 70:

        print(
            Fore.RED,
            f"{score}/100 HIGH RISK"
        )

    elif score >= 40:

        print(
            Fore.YELLOW,
            f"{score}/100 SUSPICIOUS"
        )

    else:

        print(
            Fore.GREEN,
            f"{score}/100 LOW RISK"
        )



    print("\nFindings:")


    if result["alerts"]:

        for alert in result["alerts"]:

            print(
                Fore.RED + "[!]",
                alert
            )

    else:

        print(
            Fore.GREEN +
            "[+] No suspicious indicators detected"
        )



    print("\n" + "="*75)



def main():

    for line in BANNER.splitlines():

        print(
            line.center(80)
        )


    if len(sys.argv) < 2:

        print(
            "\nUsage:"
            "\npython3 main.py <url>"
        )

        return


    report(
        sys.argv[1]
    )



if __name__ == "__main__":

    main()
