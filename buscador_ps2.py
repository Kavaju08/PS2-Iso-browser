import requests
import vt
import os
from dotenv import load_dotenv
from pathlib import Path


# ============================================================
# PS2 ISO FINDER
# Uses the archive.org API to search for games
# and the VirusTotal API to verify safety
# ============================================================

# load_dotenv() reads the .env file and loads the variables
# so we can use them with os.getenv()
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

# --- CONSTANTS ---
API_URL = "https://archive.org/advancedsearch.php"

# We read the API key from .env, never hardcode it here
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def search_games(name):
    """
    This function receives a game name and searches for it on archive.org.
    Returns a list of results.
    """

    params = {
        "q": f"title:({name}) AND mediatype:(software) AND subject:(PS2)",
        "fl[]": ["identifier", "title", "item_size"],
        "rows": 10,
        "page": 1,
        "output": "json"
    }

    print(f"\n🔍 Searching for '{name}' on archive.org...")

    try:
        response = requests.get(API_URL, params=params, timeout=10)

        if response.status_code != 200:
            print(f"❌ Error connecting to archive.org (code {response.status_code})")
            return []

        data = response.json()
        results = data.get("response", {}).get("docs", [])

        # We filter in Python to exclude platforms that are clearly not PS2
        def not_ps2(game):
            subject = game.get("subject", "")
            title = game.get("title", "")
            if isinstance(subject, list):
                subject = " ".join(subject)
            text = (subject + " " + title).upper()
            # Exclude if it explicitly mentions another platform
            other_platforms = ["PSP", "PS3", "PS4", "PS5", "XBOX", "PC", "WINDOWS", "ANDROID", "JAVA"]
            return not any(p in text for p in other_platforms)

        results = [g for g in results if not_ps2(g)]
        return results

    except requests.exceptions.ConnectionError:
        print("❌ Could not connect. Check your internet connection.")
        return []
    except requests.exceptions.Timeout:
        print("❌ The connection took too long. Please try again.")
        return []
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return []


def show_results(results):
    """
    Receives the list of results and displays them in a readable format.
    """

    if not results:
        print("😕 No results found.")
        return

    print(f"\n✅ Found {len(results)} result(s):\n")

    for i, game in enumerate(results, start=1):
        title = game.get("title", "No title")
        identifier = game.get("identifier", "")

        size_bytes = game.get("item_size", 0)
        if size_bytes:
            size_gb = round(size_bytes / (1024 ** 3), 2)
            size_str = f"{size_gb} GB"
        else:
            size_str = "Unknown size"

        link = f"https://archive.org/details/{identifier}"

        print(f"{i}. {title}")
        print(f"   📦 Size: {size_str}")
        print(f"   🔗 Link: {link}\n")


def verify_safety(identifier):
    """
    Receives the archive.org identifier and verifies the link with VirusTotal.

    VirusTotal can analyze URLs directly — we send the link
    and it tells us how many antivirus engines flag it as dangerous.
    """

    if not VIRUSTOTAL_API_KEY:
        print("❌ VirusTotal API key not found in .env")
        return

    url_to_verify = f"https://archive.org/details/{identifier}"

    print(f"\n🔍 Verifying safety with VirusTotal...")
    print(f"   URL: {url_to_verify}")

    try:
        # We create the VirusTotal client with our key
        # The "with" statement ensures the connection is properly closed when done
        with vt.Client(VIRUSTOTAL_API_KEY) as client:

            # We send the URL for analysis
            # scan_url() submits the URL to VirusTotal and returns an object with the results
            analysis = client.scan_url(url_to_verify, wait_for_completion=True)

            # Results are in last_analysis_stats
            stats = analysis.last_analysis_stats

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            clean = stats.get("undetected", 0)
            total = sum(stats.values())

            print(f"\n   📊 Analysis result ({total} antivirus engines):")

            if malicious == 0 and suspicious == 0:
                print(f"   ✅ Safe file — no antivirus flagged it as dangerous")
            elif malicious > 0:
                print(f"   🚨 DANGER! {malicious} antivirus engines flagged it as malicious")
            elif suspicious > 0:
                print(f"   ⚠️  {suspicious} antivirus engines flagged it as suspicious")

            print(f"   🟢 Clean: {clean} | 🔴 Malicious: {malicious} | 🟡 Suspicious: {suspicious}")

    except vt.error.APIError as e:
        print(f"❌ VirusTotal error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================
if __name__ == "__main__":

    print("=================================")
    print("   🎮 PS2 ISO FINDER             ")
    print("=================================")

    while True:
        search = input("\nWhat game are you looking for? (or 'exit' to quit): ").strip()

        if search.lower() == "exit":
            print("👋 Goodbye!")
            break

        if search == "":
            print("⚠️  Please enter a game name to search.")
            continue

        results = search_games(search)
        show_results(results)

        if not results:
            continue

        # Ask if they want to verify any of the results
        choice = input("Do you want to verify the safety of any result? (number or 'no'): ").strip()

        if choice.lower() == "no" or choice == "":
            continue

        # Check that a valid number was entered
        if choice.isdigit():
            index = int(choice) - 1  # subtract 1 because lists start at 0
            if 0 <= index < len(results):
                identifier = results[index].get("identifier", "")
                verify_safety(identifier)
            else:
                print("⚠️  Number out of range.")
        else:
            print("⚠️  Please enter a valid number.")