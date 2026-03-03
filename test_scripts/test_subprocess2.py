import subprocess

output = subprocess.check_output("echo hello; echo injected", shell=True)
print(output.decode())
