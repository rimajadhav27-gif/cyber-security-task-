import hashlib
import os
import json
import sys


# Function to generate SHA-256 hash of a file
def calculate_hash(file_path):
    hash_obj = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


# Create baseline hash file
def create_baseline(folder, baseline_file):
    file_hashes = {}

    print("\n📌 Creating baseline...")

    for filename in os.listdir(folder):
        full_path = os.path.join(folder, filename)

        if os.path.isfile(full_path):
            file_hashes[filename] = calculate_hash(full_path)

    with open(baseline_file, "w") as f:
        json.dump(file_hashes, f, indent=4)

    print("✅ Baseline created successfully!\n")
    print("📁 Baseline stored in:", baseline_file)


# Check for changes by comparing hashes
def check_integrity(folder, baseline_file):
    if not os.path.exists(baseline_file):
        print("❌ Baseline not found! Run this first: python file_checker.py create")
        return

    print("\n🔍 Checking file integrity...\n")

    # Load baseline
    with open(baseline_file, "r") as f:
        saved_hashes = json.load(f)

    # Get current file list
    current_files = os.listdir(folder)

    # Check for modified or missing files
    for filename, old_hash in saved_hashes.items():
        full_path = os.path.join(folder, filename)

        if not os.path.exists(full_path):
            print(f"❌ MISSING: {filename}")
            continue

        new_hash = calculate_hash(full_path)

        if new_hash == old_hash:
            print(f"✔ OK: {filename} is unchanged")
        else:
            print(f"⚠ MODIFIED: {filename} has changed!")

    # Detect new files NOT in baseline
    print("\n📎 Checking for new files...")

    for filename in current_files:
        if filename not in saved_hashes:
            print(f"➕ NEW FILE: {filename} (not in baseline)")

    print("\n✅ Integrity check completed!\n")


# Main program
if __name__ == "__main__":
    folder = "files_to_monitor"       # folder to monitor
    baseline_file = "baseline.json"   # file where hashes are saved

    if len(sys.argv) < 2:
        print("Usage: python file_checker.py [create | check]")
        sys.exit()

    option = sys.argv[1].lower()

    if option == "create":
        create_baseline(folder, baseline_file)
    elif option == "check":
        check_integrity(folder, baseline_file)
    else:
        print("Invalid option! Use:")
        print("  python file_checker.py create")
        print("  python file_checker.py check")
