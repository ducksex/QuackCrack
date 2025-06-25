from .decoders import try_all_methods
import os
import sys

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

DUCK_ART = r'''
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣉⡥⠶⢶⣿⣿⣿⣿⣷⣆⠉⠛⠿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡿⢡⡞⠁⠀⠀⠤⠈⠿⠿⠿⠿⣿⠀⢻⣦⡈⠻⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡇⠘⡁⠀⢀⣀⣀⣀⣈⣁⣐⡒⠢⢤⡈⠛⢿⡄⠻⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡇⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄⠉⠐⠄⡈⢀⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠇⢠⣿⣿⣿⣿⡿⢿⣿⣿⣿⠁⢈⣿⡄⠀⢀⣀⠸⣿⣿⣿⣿ 
⣿⣿⣿⣿⡿⠟⣡⣶⣶⣬⣭⣥⣴⠀⣾⣿⣿⣿⣶⣾⣿⣧⠀⣼⣿⣷⣌⡻⢿⣿
⣿⣿⠟⣋⣴⣾⣿⣿⣿⣿⣿⣿⣿⡇⢿⣿⣿⣿⣿⣿⣿⡿⢸⣿⣿⣿⣿⣷⠄⢻
⡏⠰⢾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⢂⣭⣿⣿⣿⣿⣿⠇⠘⠛⠛⢉⣉⣠⣴⣾
⣿⣷⣦⣬⣍⣉⣉⣛⣛⣉⠉⣤⣶⣾⣿⣿⣿⣿⣿⣿⡿⢰⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡘⣿⣿⣿⣿⣿⣿⣿⣿⡇⣼⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⢸⣿⣿⣿⣿⣿⣿⣿⠁⣿⣿⣿⣿⣿⣿⣿⣿⣿ Made by No Corazón
'''

def print_results(results):
    if not results:
        print("\n[!] No possible decodings found.\n")
        return
    print(f"\nPossible decodings found: {len(results)}\n" + "="*40)
    for i, (method, result) in enumerate(results, 1):
        print(f"{i}. Method: {method}\n{'-'*len(f'Method: {method}')}")
        print(f"{result}\n{'='*40}")

def detect_most_probable(data):
    results = try_all_methods(data)
    if not results:
        return None
    return results[0]

def welcome_screen():
    clear_screen()
    print(DUCK_ART)
    print("Welcome to QuackCrack — the decoding tool 🦆")
    print("Paste your suspicious encoded/encrypted data below.")
    print("Type 'exit' or 'quit' to leave.\n")

def main():
    while True:
        welcome_screen()
        while True:
            data = input("Enter data to analyze > ").strip()
            if data.lower() in ("exit", "quit"):
                clear_screen()
                print("Goodbye! 🦆")
                sys.exit(0)
            if not data:
                continue

            results = try_all_methods(data)
            print_results(results)

            best = detect_most_probable(data)
            if best:
                method, decoded = best
                print(f"\n>>> Most probable decoding method: {method}")
                print(f"(Unreliable) Result preview:\n{decoded[:500]}\n{'-'*40}")
            else:
                print("\n>>> No clear decoding method identified.\n")

            input("\nPress Enter to reset and analyze new data...")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye! 🦆")
        sys.exit(0)
