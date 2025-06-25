import os
import subprocess
import venv

ENV_DIR = "venv"

def create_venv():
    if not os.path.exists(ENV_DIR):
        print(f"Creating virtual environment in {ENV_DIR}...")
        venv.create(ENV_DIR, with_pip=True)
    else:
        print(f"Virtual environment {ENV_DIR} already exists.")

def install_dependencies():
    print("Installing dependencies...")
    pip = os.path.join(ENV_DIR, "Scripts" if os.name == "nt" else "bin", "pip")
    if os.path.exists("requirements.txt"):
        subprocess.check_call([pip, "install", "-r", "requirements.txt"])
    else:
        print("No requirements.txt found. Skipping dependency installation.")

def run_script(script):
    print(f"Running {script} inside the virtual environment...")
    python = os.path.join(ENV_DIR, "Scripts" if os.name == "nt" else "bin", "python")
    subprocess.run([python, script], check=True)
    print(f"{script} executed successfully.")

def main():
    target_script = "decoders.py"
    if not os.path.exists(target_script):
        print(f"Error: {target_script} not found.")
        return
    create_venv()
    install_dependencies()
    run_script(target_script)

if __name__ == "__main__":
    main()
