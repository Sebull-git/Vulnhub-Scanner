#!./polaris
# Author: Sebastian Weber
usage:"Use this if you want to want to know everything about a vulnhub machine"
description:"A script to setup the enviroment for a Vulnhub machine"


options{
"-s" "--streamer" as streamer_modus: "if you dont want your IP exposed activate that one"
"-i" "--ip" (ip_saved) as ip_saved_args = "null": "If you have an IP from your target machine, put it in therer"
"-c" "--clean" as clean: "Won't run the normal program, will just clean everything"
}
# help_functions
# print a Start of a process in green color 
let print_start(status) = print(!printf "\033[0;32m [STATUS_START] \033[0m " ~ status);
# print a test in a  color cyan color
let print_test(test) = print(!printf "\033[1;36m [[TEST]] \033[0m " ~ test);
# print a end in a yellow color
let print_end(status) = print(!printf "\033[0;33m [STATUS_END] \033[0m " ~ status);
# print a Status in a red color
let print_status(status) = print(!printf "\033[0;31m [STATUS] \033[0m " ~ status);
# print a confidential name in a purple color
let print_conf(conf) = print(!printf "\033[0;35m [CONFIDENTIAL] \033[0m " ~ conf);
# check if streamer mode is activated to hide confident items
let print_confidential(conf) = if not streamer_modus then print_conf(conf) else print_conf("HIDDEN")  

## ensures
ensure("nmap");
ensure("grep");
ensure("cut");

print(!printf "\033[0;31m author: Sebastian Weber \033[0m ");
print(!printf "\033[0;31m description: A script to setup the enviroment for a Vulnhub machine \033[0m ");
print("
 __    __       ___       ______  __  ___    .___________. __    __   _______    .______    __          ___      .__   __.  _______ .___________.
|  |  |  |     /   \     /      ||  |/  /    |           ||  |  |  | |   ____|   |   _  \  |  |        /   \     |  \ |  | |   ____||           |
|  |__|  |    /  ^  \   |  ,----'|  '  /     `---|  |----`|  |__|  | |  |__      |  |_)  | |  |       /  ^  \    |   \|  | |  |__   `---|  |----`
|   __   |   /  /_\  \  |  |     |    <          |  |     |   __   | |   __|     |   ___/  |  |      /  /_\  \   |  . `  | |   __|      |  |     
|  |  |  |  /  _____  \ |  `----.|  .  \         |  |     |  |  |  | |  |____    |  |      |  `----./  _____  \  |  |\   | |  |____     |  |     
|__|  |__| /__/     \__\ \______||__|\__\        |__|     |__|  |__| |_______|   | _|      |_______/__/     \__\ |__| \__| |_______|    |__|     
                                                                                                                                                 

")
print("")
print("")

if clean then{
    if (!ls | grep "target_scan.txt") == ("target_scan.txt") then {!rm "target_scan.txt"} else {print_status("No target_scan.txt found")}
    if (!ls | grep "temp.txt") == ("temp.txt") then {!rm "temp.txt"} else {print_status("No temp.txt found")}
    exit(0)
    }
else
    {}

# Starting
print_status("Starting...")

## nmap scan

# get ip = 192.168.56.1/24
print_start("Getting IP...")
let get_ip() = !ip "address" | grep "vboxnet0" | grep "inet"  | cut "-d" " " "-f" 6
print_confidential(get_ip())
print_end("Got ip")

# get network_range = 192.168.1-254
print_start("Getting IP Range...")
let get_network_range() = !python "-c" ("print('" ~ get_ip() ~ "'[:-3]+'-254')")
print_confidential(get_network_range()) 
print_end("Got IP Range")


let ip = if (ip_saved == null) then{
    # network scan to find the machine
    print_start("Scanning Network...")
    let nmap_network_scan() = !nmap "-T4" "-oG" "temp.txt" (get_network_range())
    let nmap_network_scaned = nmap_network_scan() 
    print_end("Scanned Network...")
    print(!cat "temp.txt" | grep "Ports")
    print_status("These are the found ips, choose one by typing the IP")
    print_status("Please type in the IP")
    !rm "temp.txt"
    readLine()
}
else{
    ip_saved
}


# Aggresive Scan
print_start("Aggresivly scanning the machine...")
let nmap_hard_scan(ip) = !nmap "-T4" "-A" "--script=vuln" "-v"  "-oN" "target_scan.txt" ip
print(nmap_hard_scan(ip))
print_end("Scanned  Machine...")
print_status("Here is the outputfile" ~ !ls | grep "target_scan.txt")

# TODO 
## nikto scanner for webserver (port 80 or http)
## gobuster for webserver
## if ip address doesn't fit pattern error
## put report together

# Clean
