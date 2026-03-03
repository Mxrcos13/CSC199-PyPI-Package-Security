import subprocess

pe = 'orte; echo Injected'
cmd = f"echo job | qsub -pe {pe} 4"

print(cmd)

try:
    output = subprocess.check_output(
        cmd,
        shell=True,
        stderr=subprocess.STDOUT
    )
    print(output.decode())
except subprocess.CalledProcessError as e:
    print("Command failed, but output was:")
    print(e.output.decode())
