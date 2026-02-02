### Goals
- [x] Setup Environment
- [x] Research and install tools
- [x] Research Command Injections in Python
- [x] Review CVE Reports
- [x] Study CVSS scoring
- [x] Read Responsible disclosure guides
- [x] Analyze vulnerable code samples
sort by downloads
search by os.system search in github
source and sink

### Notes
#### Disclosure 
![[Pasted image 20260202120921.jpg]]

#### Command Injection 
- Below is an example of a vulnerable  script using the os.system() Parameter. This command was intended to print a users input but can be used to embed commands as there is no input validation or sanitization. 
```python
# Vulnerability: Dynamically constructing commands without sanity checks.
user_input = input("Enter a parameter: ")
command = f"echo Printing {user_input}"
os.system(command)
```
- Below is another example of an vulnerable script where the eval() method is used. without proper sanitization a user can input the following to run arbitrary commands on the system `__import__('os').popen('ls').read()`
```python
# Vulnerability: Insecure use of the eval() method.
user_input = input("Enter a Python expression to evaluate: ")
try:
    result = eval(user_input)
    print(f"Result:\n{result}")
except Exception as e:
    print(f"Error:\n{e}")
```
- below shows how the subprocess module allows for the start of new processes with user input. This can also lead to a command injection vulnerability.
``` python
# Vulnerable  
user_input = "foo && cat /etc/passwd" # value supplied by user  
subprocess.call("grep -R {} .".format(user_input), shell=True)  
  
# Vulnerable  
user_input = "cat /etc/passwd" # value supplied by user  
subprocess.run(["bash", "-c", user_input], shell=True)
```
### CVSS
| **CVSS Base Score** | **CVSS Severity Level** |
| ------------------- | ----------------------- |
| 0                   | None                    |
| 0.1 - 3.9           | Low                     |
| 4.0 - 6.9           | Medium                  |
| 7.0 - 8.9           | High                    |
| 9.0 - 10.0          | Critical                |
Based on the following factors
- Attack Vector
- Attack Complexity
- Privileges Required
- User Interaction
- Scope
- Confidentiality
- Integrity
- Availability
#### Attack Vector
The attack vector has 4 different values that can be assigned to it:
- Network,
- Adjacent,
- Local, or
- Physical.
#### Attack Complexity
Attack Complexity comes down to how hard it is to exploit the vulnerability. Two possible values exist for this, which are:
- Low or
- High.
#### Privileges Required
This outlines what privileges the attacker needs to have BEFORE exploiting the vulnerability. Possible values are:
- None,
- Low, or
- High.
#### User Interaction
This defines how a user needs to be engaged somehow to successfully exploit the vulnerability. The options here are:
- None or
- Required.
#### Scope
This is a slightly harder sub-component to understand. Here it is trying to measure if the vulnerability can impact items that are outside of the security authority of the affected component. A security authority is something that controls access to objects under its control. Examples of a security authority could be an application (controls how things work inside the application), an operating system (controls how things work within the environment). Values here are:
- Unchanged or
- Changed
#### Confidentiality
Confidentiality is the potential for unauthorized access to sensitive information. The possible values are:
- High,
- Low, or
- None.
#### Integrity
This component measures the potential for unauthorized modification, a data breach or deletion of data. Potential values are:
- High,
- Low, or
- None.
#### Availability
Availability attempts to measure the potential for denial of access to authorized users. This could be the denial access to a service or processor cycles. Potential values for Availability are:
- High,
- Low, or
- None.