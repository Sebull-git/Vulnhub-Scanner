#!./polaris
# Author: Sebastian Weber
# Description: A script to setup the enviroment for a Vulnhub machine

options{
"-s" "--streamer" as streamer_modus: "if you dont want your IP exposed activate that one"
"-i" "--ip" (ip_saved) as ip_saved_args = "null": "If you have an IP from your target machine, put it in therer"
}
print("Hack the Planet Script");

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


# nikto scanner for webserver (port 80 or http)
# gobuster for webserver

