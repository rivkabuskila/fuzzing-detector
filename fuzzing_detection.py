import re
import time
from datetime import datetime
from pathlib import Path
"""
A script that performs Fuzzing detection
rivka buskila 206701187
"""


COUNTER=0
CHECK=""

"""
After checking the log after fuzzing ssh attacks I discovered that there are 3 messages that repeat themselves if the attack takes place (different attacks):
1. kex_exchange_identification: Can happen for a number of reasons:
The socket connection between the SSH server and the client is disconnected.
Add damaged equipment or device to an existing network.
The SSH daemon can consume an unreasonably large amount of network resources.
Your ports may be overly exhausted by connection requests.
2. kex_input_kexinit: This indicates a denial of service vulnerability in the SSH1 protocol implementation in OpenSSH.
The vulnerability is caused by improper implementation of a function in the kex module. A remote attacker may be able to exploit this to cause a denial of service condition on the affected system.
3. Connection closed by - The customer closes the connection several times in a row.
"""
def check_line(x:str):
    global COUNTER
    if (x.find("kex_exchange_identification")!=-1):
        COUNTER+=1
    elif (x.find("kex_input_kexinit")!=-1):
        COUNTER+=1
    elif (x.find("Connection closed by ")!=-1):
        index = x.find("Connection closed by ")
        index2 = x.find("port")
        global CHECK
        if CHECK == "":
            COUNTER+=1
        elif CHECK == x[index:index2]:
            COUNTER+=1
        CHECK = x[index:index2]
    """
The function goes to the \var\log folder and from there reads from auth.log.
Saves the current date and time and checks by regular expression where in the log the date is (or close to it).
Each line from the current date to the end of the log the function sends to the function check_line and checks if there is a greater quantity than five of the suspect strings that are present when there is ssh fuzzing
"""
def read_log():
    p = Path('/var/log')
    filename = p / "auth.log"
    now = datetime.now()
    current_time = now.strftime("%b %d %H:%M:%S")
    time_re = re.compile(r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)+\s+\d+\s+\d+:\d+:\d+')
    current_time = time.strptime(current_time, "%b %d %H:%M:%S")
    with open(filename, "r") as fh:
     for line in fh.readlines():
        match = time_re.search(line)       #find the current time
        if match:
           matchDate = match.group()
           matchDate = time.strptime(matchDate, "%b %d %H:%M:%S")
           if matchDate >= current_time:
               check_line(match.string.strip())
               if COUNTER > 10:
                     print("Fuzzing detected")
                     exit()
if __name__ == '__main__':
    while True:
     read_log()