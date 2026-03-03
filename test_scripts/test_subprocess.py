import subprocess

output = subprocess.check_output("echo hello", shell=True)
print(output.decode())
