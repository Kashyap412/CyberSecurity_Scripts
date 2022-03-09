from time import sleep
from base.KashY_Functions import *

clear()

Banner("IOC Dump Collection")

a=input('\tEnter 1 for Daily IOC Dump\n\tEnter 2 for Bulk IOC Dump\n\tEnter 3 for Both\n\n\n\tEnter Number\t:\t')

if a==1 :
    daily_ioc_dump()
    End_Banner()
if a==2 :
    dump_iocs_once()
    End_Banner()
if a==3 :
    daily_ioc_dump()
    dump_iocs_once()
    End_Banner()
else :
    clear()
    print("\n\t\tExiting Script ...\n")
    sleep(1)
    clear()
    sys.exit(1)
    