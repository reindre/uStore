import os
import subprocess
import threading


def add_and_commit(folder):
    """Add and commit a single folder."""
    subprocess.run(["git", "add", "--sparse", folder], check=True)
    subprocess.run(["git", "commit", "-m", f"Add files"], check=True)


def push():
    """Push commits to remote."""
    subprocess.run(["git", "push"], check=True)


current_path = os.getcwd()
entries = os.listdir(current_path)
folders = [f for f in entries if os.path.isdir(os.path.join(current_path, f))]
if ".git" in folders:
    folders.remove(".git")

if not folders:
    print("No folders to process.")
    exit()

add_and_commit(folders[0])

for prev, nxt in zip(folders, folders[1:]):
    push_proc = subprocess.Popen(["git", "push"])
    commit_thread = threading.Thread(target=add_and_commit, args=(nxt,))
    commit_thread.start()
    push_proc.wait()
    commit_thread.join()

push()
