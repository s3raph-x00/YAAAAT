### Author: s3raph
### Purpose: To Pass the Butter
### Version: .05
### Date Since I Remebered to Update: 20211108

import os
import shutil
import sys
import json
import getopt
import glob
import hashlib
import re
from zipfile import ZipFile
from struct import pack, unpack
from xml.sax.saxutils import escape
import traceback

### Error Control For Soft Process Failure
def func_fail_whale():
    var_current_function = "func_fail_whale"
    print("▄██████████████▄▐█▄▄▄▄█▌")
    print("██████▌▄▌▄▐▐▌███▌▀▀██▀▀")
    print("████▄█▌▄▌▄▐▐▌▀███▄▄█▌")
    print("▄▄▄▄▄██████████████")
    time.sleep(.5) 
    print("Something Bad Happened")
    time.sleep(.3)
    print("Trying Again...")
    time.sleep(.5)
    return

### ASCII Art Pulled from SSt @ascii.co.uk/art/whale
### Error Control For Hard Process Failure
def func_hard_fail_whale():
    print("      __________...----..____..--``-..___")
    print("    , .                                  ```--.._")
    print("   :    (-)                                      ``._")
    print("   |    GIANT FAIL WHALE       --                    ``.")
    print("   |                   -.-      -.     -   -.        `. :")
    print("   |                     __           --            .    :")
    print("    `._____________     (  `.   -.-      --  -   .   `    :")
    print("       `------------------   /_.--------..__..--.._ `. `.  :")
    print("                          `---                     `-._ .  |")
    print("                                                       `.` |")
    print("                                                         |`|")
    print("                                                          ||")
    print("                                                          /|`.")
    print("                                                         / _|-")
    print("                                                        /_,")
    time.sleep(.5) 
    print("Something Really Bad Happened")
    time.sleep(.3)
    print("Program Exiting (Harvest The Logs)")
    time.sleep(.5)
    exit

### Checking Python Version - Initial ###
def func_python_version_check():
    var_current_function = "func_python_version_check"
    if sys.version_info >= (2, 7, 0):
        var_python_version_check = "TRUE"
        var_python_version_info = "2.7+"
    if sys.version_info >= (3, 0, 0):
        var_python_version_check = "TRUE"
        var_python_version_info = "3.0+"   
    else:
        print("Python Version Does Not Appear to Be Supported")
        print("Python 2.7+ or 3.1+ is a requirement")
        func_hard_fail_whale()

### This Function Does Some O/S Checks ###
def func_determine_operating_system():
    var_current_function = "func_determine_operating_system"
    try:
        var_OS_ver_A = platform.system()
        var_OS_ver_B = os.name
        var_OS_ver_C = sys.platform
        var_OS_main_ver = "O/S: " + var_OS_ver_A + " " + var_OS_ver_B.upper + ": " + var_OS_ver_C
        var_PY_ver_A = platform.python_version()
        var_PY_ver_B = sys.version
        var_PY_ver_C = sys.version_info
        var_PY_ver_D = platform.python_implementation() ## Unused But Potentially Relevant Data Point for TroubleShooting
        print(var_OS_main_ver)
        print("Python Version is: " + var_PY_ver_A)
        print("Full Python Info is: " + var_PY_ver_B)
        print("Additional Python Details: " + var_PY_ver_C)
    except:
        var_manual_error_code = 1
        print("Operating System Determination Failed")
        print("//Missing Core Python libraries or Permissions may be the issue//")
        time.sleep(.5)
        func_hard_fail_whale()

### Console/Error Text Color ###
def func_set_console_color_for_errors():
    if var_manual_error_code == (0): ## This Means Normal Operation
        os.system('color 70') 
        return
    if var_manual_error_code == (1): ## This Means Major Error (Hard Fail)
        func_set_console_strobe()
        os.system('color 4F') 
        func_hard_fail_whale()
    if var_manual_error_code == (2): ## This Means Minor Error (Attempting to Recover)
        func_fail_whale()
    else:
        print("Error")

def func_set_console_strobe():
    var_current_function = "func_set_console_strobe"    
    os.system('color 7C')
    time.sleep(.2)
    os.system('color C7')
    time.sleep(.2)
    os.system('color 7C') 
    time.sleep(.2)
    os.system('color C7')
    time.sleep(.2)
    os.system('color 7C')
    time.sleep(.2)

def func_global_var_declare():
    ### REGEX Global Varible Declaration and Assignment ###
    global var_ipv4_regex_pattern
    global var_ipv6_regex_pattern
    global var_phonenum_regex_pattern
    global possible_bitcoinaddr_regex_pattern
    global possible_default_password_regex_pattern
    global possible_email_regex_pattern
    global possible_ftp_hiconf_regex_pattern
    global possible_macaddr_regex_pattern
    global possible_ssh_hiconf_regex_pattern
    global possible_ssn_regex_pattern
    global possible_url_hiconf_regex_pattern
    global possible_url_lowconf_regex_pattern

    var_ipv4_regex_pattern = re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    var_ipv6_regex_pattern = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
    var_phonenum_regex_pattern = re.compile('^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$')
    possible_default_password_regex_pattern = re.compile('^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$')
    possible_ssn_regex_pattern = re.compile('^(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}$')
    possible_url_hiconf_regex_pattern = re.compile('https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)')
    possible_url_lowconf_regex_pattern = re.compile('(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)')
    possible_ftp_hiconf_regex_pattern = re.compile('ftps?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)')
    possible_ssh_hiconf_regex_pattern = re.compile('ssh:\/\/(@\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b')
    possible_bitcoinaddr_regex_pattern = re.compile('^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$')
    possible_macaddr_regex_pattern = re.compile('^[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}$')
    possible_email_regex_pattern = re.compile('(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))')

    ### JSON Global Variable Declaration ###
    global tuple_contained_libraries
    global tuple_arch_support
    global tuple_arm64_libaries
    global tuple_arm64_lib_md5
    global tuple_arm64_lib_sha256
    global tuple_arm32_libaries
    global tuple_arm32_lib_md5
    global tuple_arm32_lib_sha256
    global tuple_x64_libaries
    global tuple_x64_lib_md5
    global tuple_x64_lib_sha256
    global tuple_contained_assets
    global tuple_contained_assets_md5
    global tuple_contained_assets_sha256
    global tuple_directory_listing
    global tuple_directory_file_listing

    ### Known File Locations For Rip ###
    global rsa_cert_file_dump_txt
    global cert_content_extract_sub
    global cert_content_extract_serial
    global cert_content_extract_algorithm
    global cert_content_extract_notbefore
    global cert_content_extract_notafter

    ### Script Functionality Global Variable Declaration And Assignment ###
    global inputdirectory
    global log_txt_update
    global case_log_file_txt
    global var_manual_error_code
    inputdirectory_var = ''

def func_apk_json_map():
    apk_json = {
        "FILE- Filename": "",
        "FILE- True Filename": "",
        "FILE- Package Name": "",
        "FILE- Reported Location": "",
        "FILE- Reported Device": "",
        "FILE- Contained Libraries": (tuple_contained_libraries), #Tuple
        "FILE- Supported Architectures": (tuple_arch_support), #Tuple
        "FILE- Contained Libraries ARM64": (tuple_arm64_libaries), #Tuple
        "HASH- MD5 of Contained Libraries ARM64": (tuple_arm64_lib_md5), #Tuple
        "HASH- SHA256 of Contained Libraries ARM64": (tuple_arm64_lib_sha256), #Tuple
        "FILE- Contained Libraries ARM32": (tuple_arm32_libaries), #Tuple
        "HASH- MD5 of Contained Libraries ARM32": (tuple_arm32_lib_md5), #Tuple
        "HASH- SHA256 of Contained Libraries ARM32": (tuple_arm32_lib_sha256), #Tuple
        "FILE- Contained Libraries x86": (tuple_x86_libaries), #Tuple
        "HASH- MD5 of Contained Libraries x86": (tuple_x86_lib_md5), #Tuple
        "HASH- SHA256 of Contained Libraries x86": (tuple_x86_lib_sha256), #Tuple
        "FILE- Contained Libraries x64": (tuple_x64_libaries), #Tuple
        "HASH- MD5 of Contained Libraries x64": (tuple_x64_lib_md5), #Tuple
        "HASH- SHA256 of Contained Libraries x64": (tuple_x64_lib_sha256), #Tuple
        "FILE- Contained Assets": (tuple_contained_assets), #Tuple
        "HASH- MD5 of Contained Assets": (tuple_contained_assets_md5), #Tuple
        "HASH- SHA256 of Contained Assets": (tuple_contained_assets_sha256), #Tuple
        "FILE- Directory Listing": (tuple_directory_listing), #Tuple
        "FILE- Directory And File Listing": (tuple_directory_file_listing), #Tuple
        "HASH- MD5 Hash": "",
        "HASH- SHA1 Hash": "",
        "HASH- SHA256 Hash": "",
        "HASH- SHA512 Hash": "",
        "CERT- APK Signature Subject": "",
        "CERT- APK Signature Serial": "",
        "PERM- ACCEPT_HANDOVER": FALSE,
        "PERM- ACCESS_BACKGROUND_LOCATION": FALSE,
        "PERM- ACCESS_BLOBS_ACROSS_USERS": FALSE,
        "PERM- ACCESS_CHECKIN_PROPERTIES": FALSE,
        "PERM- ACCESS_COARSE_LOCATION": FALSE,
        "PERM- ACCESS_FINE_LOCATION": FALSE,
        "PERM- ACCESS_LOCATION_EXTRA_COMMANDS": FALSE,
        "PERM- ACCESS_MEDIA_LOCATION": FALSE,
        "PERM- ACCESS_NETWORK_STATE": FALSE,
        "PERM- ACCESS_NOTIFICATION_POLICY": FALSE,
        "PERM- ACCESS_WIFI_STATE": FALSE,
        "PERM- ADD_VOICEMAIL": FALSE,
        "PERM- ACCOUNT_MANAGER": FALSE,
        "PERM- ACTIVITY_RECOGNITION": FALSE,
        "PERM- ANSWER_PHONE_CALLS": FALSE,
        "PERM- BATTERY_STATS": FALSE,
        "PERM- BIND_ACCESSIBILITY_SERVICE": FALSE,
        "PERM- BIND_APPWIDGET": FALSE,
        "PERM- BIND_AUTOFILL_SERVICE": FALSE,
        "PERM- BIND_CALL_REDIRECTION_SERVICE": FALSE,
        "PERM- BIND_CARRIER_MESSAGING_CLIENT_SERVICE": FALSE,
        "PERM- BIND_CARRIER_MESSAGING_SERVICE": FALSE,
        "PERM- BIND_CARRIER_SERVICES": FALSE,
        "PERM- BIND_CHOOSER_TARGET_SERVICE": FALSE,
        "PERM- BIND_COMPANION_DEVICE_SERVICE": FALSE,
        "PERM- BIND_CONDITION_PROVIDER_SERVICE": FALSE,
        "PERM- BIND_CONTROLS": FALSE,
        "PERM- BIND_DEVICE_ADMIN": FALSE,
        "PERM- BIND_DREAM_SERVICE": FALSE,
        "PERM- BIND_INCALL_SERVICE": FALSE,
        "PERM- BIND_INPUT_METHOD": FALSE,
        "PERM- BIND_MIDI_DEVICE_SERVICE": FALSE,
        "PERM- BIND_NFC_SERVICE": FALSE,
        "PERM- BIND_NOTIFICATION_LISTENER_SERVICE": FALSE,
        "PERM- BIND_PRINT_SERVICE": FALSE,
        "PERM- BIND_QUICK_ACCESS_WALLET_SERVICE": FALSE,
        "PERM- BIND_QUICK_SETTINGS_TILE": FALSE,
        "PERM- BIND_REMOTEVIEWS": FALSE,
        "PERM- BIND_SCREENING_SERVICE": FALSE,
        "PERM- BIND_TELECOM_CONNECTION_SERVICE": FALSE,
        "PERM- BIND_TEXT_SERVICE": FALSE,
        "PERM- BIND_TV_INPUT": FALSE,
        "PERM- BIND_VISUAL_VOICEMAIL_SERVICE": FALSE,
        "PERM- BIND_VOICE_INTERACTION": FALSE,
        "PERM- BIND_VPN_SERVICE": FALSE,
        "PERM- BIND_VR_LISTENER_SERVICE": FALSE,
    	"PERM- BIND_WALLPAPER": FALSE,
    	"PERM- BLUETOOTH": FALSE,
    	"PERM- BLUETOOTH_ADMIN": FALSE,
    	"PERM- BLUETOOTH_ADVERTISE": FALSE,
        "PERM- BLUETOOTH_CONNECT": FALSE,
	    "PERM- BLUETOOTH_PRIVILEGED": FALSE,
        "PERM- BLUETOOTH_SCAN": FALSE,
        "PERM- BODY_SENSORS": FALSE,
        "PERM- BROADCAST_PACKAGE_REMOVED": FALSE,
    	"PERM- BROADCAST_SMS": FALSE,
        "PERM- BROADCAST_STICKY": FALSE,
	    "PERM- BROADCAST_WAP_PUSH": FALSE,
	    "PERM- CALL_COMPANION_APP": FALSE,
        "PERM- CALL_PHONE": FALSE,
        "PERM- CALL_PRIVILEGED": FALSE,
        "PERM- CAMERA": FALSE,
	    "PERM- CAPTURE_AUDIO_OUTPUT": FALSE,
	    "PERM- CHANGE_COMPONENT_ENABLED_STATE": FALSE,
        "PERM- CHANGE_CONFIGURATION": FALSE,
        "PERM- CHANGE_NETWORK_STATE": FALSE,
        "PERM- CHANGE_WIFI_MULTICAST_STATE": FALSE,
	    "PERM- CHANGE_WIFI_STATE": FALSE,
	    "PERM- CLEAR_APP_CACHE": FALSE,
        "PERM- CONTROL_LOCATION_UPDATES": FALSE,
	    "PERM- DELETE_CACHE_FILES": FALSE,
        "PERM- DELETE_PACKAGES": FALSE,
    	"PERM- DIAGNOSTIC": FALSE,
        "PERM- DISABLE_KEYGUARD": FALSE,
    	"PERM- DUMP": FALSE,
    	"PERM- EXPAND_STATUS_BAR": FALSE,
    	"PERM- FACTORY_TEST": FALSE,
    	"PERM- FOREGROUND_SERVICE": FALSE,
    	"PERM- GET_ACCOUNTS": FALSE,
        "PERM- GET_ACCOUNTS_PRIVILEGED": FALSE,
	    "PERM- GET_PACKAGE_SIZE": FALSE,
	    "PERM- GET_TASKS": FALSE,
	    "PERM- GLOBAL_SEARCH": FALSE,
	    "PERM- HIDE_OVERLAY_WINDOWS": FALSE,
	    "PERM- HIGH_SAMPLING_RATE_SENSORS": FALSE,
	    "PERM- INSTALL_LOCATION_PROVIDER": FALSE,
	    "PERM- INSTALL_PACKAGES": FALSE,
	    "PERM- INSTALL_SHORTCUT": FALSE,
	    "PERM- INSTANT_APP_FOREGROUND_SERVICE": FALSE,
        "PERM- INTERACT_ACROSS_PROFILES": FALSE,
	    "PERM- INTERNET": FALSE,
        "PERM- KILL_BACKGROUND_PROCESSES": FALSE,
	    "PERM- LAUNCH_TWO_PANE_SETTINGS_DEEP_LINK": FALSE,
        "PERM- LOADER_USAGE_STATS": FALSE,
	    "PERM- LOCATION_HARDWARE": FALSE,
	    "PERM- MANAGE_DOCUMENTS": FALSE,
        "PERM- MANAGE_EXTERNAL_STORAGE": FALSE,
        "PERM- MANAGE_MEDIA": FALSE,
	    "PERM- MANAGE_ONGOING_CALLS": FALSE,
        "PERM- MANAGE_OWN_CALLS": FALSE,
	    "PERM- MASTER_CLEAR": FALSE, # Unusual Call
	    "PERM- MEDIA_CONTENT_CONTROL": FALSE,
	    "PERM- MODIFY_AUDIO_SETTINGS": FALSE,
	    "PERM- MODIFY_PHONE_STATE": FALSE,
	    "PERM- MOUNT_FORMAT_FILESYSTEMS": FALSE,
        "PERM- MOUNT_UNMOUNT_FILESYSTEMS": FALSE,
        "PERM- NFC": FALSE,
	    "PERM- NFC_PREFERRED_PAYMENT_INFO": FALSE,
	    "PERM- NFC_TRANSACTION_EVENT": FALSE,
        "PERM- PACKAGE_USAGE_STATS": FALSE,
	    "PERM- PERSISTENT_ACTIVITY": FALSE,
	    "PERM- PROCESS_OUTGOING_CALLS": FALSE,
	    "PERM- QUERY_ALL_PACKAGES": FALSE,
	    "PERM- READ_CALENDAR": FALSE,
	    "PERM- READ_CALL_LOG": FALSE,
        "PERM- READ_CONTACTS": FALSE,
	    "PERM- READ_EXTERNAL_STORAGE": FALSE,
	    "PERM- READ_INPUT_STATE": FALSE,
        "PERM- READ_LOGS": FALSE,
	    "PERM- READ_PHONE_NUMBERS": FALSE,
	    "PERM- READ_PHONE_STATE": FALSE,
	    "PERM- READ_PRECISE_PHONE_STATE": FALSE,
	    "PERM- READ_SMS": FALSE,
        "PERM- READ_SYNC_SETTINGS": FALSE,
        "PERM- READ_SYNC_STATS": FALSE,
        "PERM- READ_VOICEMAIL": FALSE,
	    "PERM- REBOOT": FALSE,
	    "PERM- RECEIVE_BOOT_COMPLETED": FALSE,
        "PERM- RECEIVE_MMS": FALSE,
	    "PERM- RECEIVE_SMS": FALSE,
	    "PERM- RECEIVE_WAP_PUSH": FALSE,
	    "PERM- RECORD_AUDIO": FALSE,
	    "PERM- REORDER_TASKS": FALSE,
        "PERM- REQUEST_COMPANION_PROFILE_WATCH": FALSE,
	    "PERM- REQUEST_COMPANION_RUN_IN_BACKGROUND": FALSE,
        "PERM- REQUEST_COMPANION_START_FOREGROUND_SERVICES_FROM_BACKGROUND": FALSE,
        "PERM- REQUEST_COMPANION_USE_DATA_IN_BACKGROUND": FALSE,
	    "PERM- REQUEST_DELETE_PACKAGES": FALSE,
	    "PERM- REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": FALSE,
	    "PERM- REQUEST_INSTALL_PACKAGES": FALSE,
        "PERM- REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE": FALSE,
        "PERM- REQUEST_PASSWORD_COMPLEXITY": FALSE,
	    "PERM- RESTART_PACKAGES": FALSE,
	    "PERM- SCHEDULE_EXACT_ALARM": FALSE,
        "PERM- SEND_RESPOND_VIA_MESSAGE": FALSE,
	    "PERM- SEND_SMS": FALSE,
	    "PERM- SET_ALARM": FALSE,
        "PERM- SET_ALWAYS_FINISH": FALSE,
	    "PERM- SET_ANIMATION_SCALE": FALSE,
	    "PERM- SET_DEBUG_APP": FALSE,
        "PERM- SET_PREFERRED_APPLICATIONS": FALSE,
        "PERM- SET_PROCESS_LIMIT": FALSE,
	    "PERM- SET_TIME": FALSE,
	    "PERM- SET_TIME_ZONE": FALSE,
	    "PERM- SET_WALLPAPER": FALSE,
	    "PERM- SET_WALLPAPER_HINTS": FALSE,
        "PERM- SIGNAL_PERSISTENT_PROCESSES": FALSE,
	    "PERM- SMS_FINANCIAL_TRANSACTIONS": FALSE,
        "PERM- START_FOREGROUND_SERVICES_FROM_BACKGROUND": FALSE,
	    "PERM- START_VIEW_PERMISSION_USAGE": FALSE,
	    "PERM- STATUS_BAR": FALSE,
        "PERM- SYSTEM_ALERT_WINDOW": FALSE,
        "PERM- TRANSMIT_IR": FALSE,
	    "PERM- UNINSTALL_SHORTCUT": FALSE, # Odd
	    "PERM- UPDATE_DEVICE_STATS": FALSE,
        "PERM- UPDATE_PACKAGES_WITHOUT_USER_ACTION": FALSE,
        "PERM- USE_BIOMETRIC": FALSE,
	    "PERM- USE_FINGERPRINT": FALSE,
	    "PERM- USE_FULL_SCREEN_INTENT": FALSE,
        "PERM- USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER": FALSE,
	    "PERM- USE_SIP": FALSE,
	    "PERM- UWB_RANGING": FALSE,
	    "PERM- VIBRATE": FALSE,
	    "PERM- WAKE_LOCK": FALSE,
	    "PERM- WRITE_APN_SETTINGS": FALSE,
        "PERM- WRITE_CALENDAR": FALSE,
	    "PERM- WRITE_CALL_LOG": FALSE,
	    "PERM- WRITE_CONTACTS": FALSE,
	    "PERM- WRITE_EXTERNAL_STORAGE": FALSE,
	    "PERM- WRITE_GSERVICES": FALSE,
        "PERM- WRITE_SECURE_SETTINGS": FALSE,
	    "PERM- WRITE_SETTINGS": FALSE,
	    "PERM- WRITE_SYNC_SETTINGS": FALSE,
	    "PERM- WRITE_VOICEMAIL": FALSE
    }

def func_android_cert_pull():
    rsa_cert_file_var_text = subprocess.check_output(".\\win\\openssl.exe pkcs7 -inform DER -in " + rsa_cert_file_dump_txt + " -noout -print_certs -text")
    var_cert_content = []
    for line_rsa_cert_file_var_text in rsa_cert_file_var_text:
        var_cert_content.append(line_rsa_cert_file_var_text.rstrip())

    var_cert_content_munged = "".join(str(x) for x in var_cert_content)
    
    cert_content_extract_sub = re.findall('Subject:(.*?)SubjectPublicKeyInfo', var_cert_content_munged)
    cert_content_extract_serial = re.findall('SerialNumber:(.*?)SignatureAlgorithm:', var_cert_content_munged)
    cert_content_extract_algorithm = re.findall('PublicKeyAlgorithm:(.*?)EncryptionRSAPublicKey:', var_cert_content_munged)
    cert_content_extract_notbefore = re.findall('ValidityNotBefore:(.*?)NotAfter:', var_cert_content_munged)
    cert_content_extract_notafter = re.findall('NotAfter:(.*?)Subject:', var_cert_content_munged)

def func_clean_up():
    ### Final Cleanup ###
    log_txt_update.close()
    timestr2 = time.strftime("%Y%m")
    if timestr2 == "202212":
        easteregg()

def func_initial_logging():
    case_log_file_txt = var_case_delivery_directory + "\\log.txt"
    log_txt_update = open(case_log_file_txt, "a")
    log_txt_update.write("--- APK Ripper Script Started ---\n")

def main(argv):
    func_global_var_declare()

    try:
        opts, args = getopt.getopt(argv,"hi:",["idir="])
    except getopt.GetoptError:
        var_manual_error_code = (1)
        func_fail_whale()
        print("YAAAAT_apk_ripper.py -i <directory_to_scan_for_apks>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("YAAAAT_apk_ripper.py -i <directory_to_scan_for_apks>")
            sys.exit()
        elif opt in ("-i", "--idir"):
            inputdirectory_var = arg

    inputdirectory = os.path.dirname(inputdirectory_var)
    var_case_delivery_directory = inputdirectory + "\\" + "_case_info"
    try:
        os.mkdir(var_case_delivery_directory)
    except:
        print("[WARN]: Error Making Main Case Directory, likely already exists: " + var_case_delivery_directory)

    func_initial_logging()

    
    directory_search_pattern_check = (inputdirectory+"\\apk_storage\\")
    if os.path.isdir(directory_search_pattern_check):
        directory_search_pattern = (inputdirectory+"\\apk_storage\\*.apk")
        log_txt_update.write("[INFO]: Searching for APKs in: " + directory_search_pattern + "\n")
    else:
        directory_search_pattern = (inputdirectory+"\\*.apk")
        log_txt_update.write("[INFO]: Searching for APKs in: " + directory_search_pattern + "\n")

    for apk_full_path in glob.glob(directory_search_pattern):
        apk_with_extension = os.path.basename(apk_full_path)
        apk, discard_ext = os.path.splitext(apk_with_extension)
        log_txt_update.write("[INFO]: Found The APK: " + apk_with_extension + " - Processing Now\n")

        apk_main_dir = inputdirectory + "\\apk_post_run\\"
        try:
            os.mkdir(apk_main_dir)
        except:
            log_txt_update.write("[WARN]: Error Making APK Post-Run Directory, likely already exists: " + apk_main_dir + "\n")

        apk_main_dir_apk = inputdirectory + "\\apk_post_run\\" + apk
        try:
            os.mkdir(apk_main_dir_apk)
        except:
            log_txt_update.write("[WARN]: Error Making APK Main Directory, likely already exists: " + apk_main_dir_apk + "\n")
            
        apk_source_directory = apk_main_dir_apk + "\\" + "_0_source"
        try:
            os.mkdir(apk_source_directory)
        except:
            log_txt_update.write("[WARN]: Error Making APK Source Directory, likely already exists: " + apk_source_directory + "\n")
            
        apk_decomp_directory = apk_main_dir_apk + "\\" + "_1_decomp"
        try:
            os.mkdir(apk_decomp_directory)
        except:
            log_txt_update.write("[WARN]: Error Making APK Decomp Directory, likely already exists: " + apk_decomp_directory + "\n")

        apk_results_directory = apk_main_dir_apk + "\\" + "_2_results"
        try:
            os.mkdir(apk_results_directory)
        except:
            log_txt_update.write("[WARN]: Error Making APK Results Directory, likely already exists: " + apk_results_directory + "\n")

        apk_extract_directory = apk_main_dir_apk + "\\" + "_3_extract"
        try:
            os.mkdir(apk_extract_directory)
        except:
            log_txt_update.write("[WARN]: Error Making APK Extract Directory, likely already exists: " + apk_extract_directory + "\n")
        
        var_information_true_filename = apk_with_extension[9:]
        hashes_file_dump_txt = apk_results_directory + "\\" + apk + "_info.txt"
        hashes_file_dump_csv = apk_results_directory + "\\" + apk + "_info.csv"
        jadx_ip_extract_txt = apk_results_directory + "\\" + apk + "_regex_IPs.txt"
        jadx_ip_extract_csv = apk_results_directory + "\\" + apk + "_regex_IPs.csv"

        var_information_filename_write = ("[INFO]: True APK Filename is: " + var_information_true_filename + "\n")
        log_txt_update.write("[INFO]: True APK Filename is: " + var_information_true_filename + "\n")
        file_txt_update = open(hashes_file_dump_txt, "a")
        file_txt_update.write(var_information_filename_write)

        md5_hash = hashlib.md5()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                md5_hash.update(byte_block)
            apk_md5_hash = md5_hash.hexdigest()
            var_information_md5hash_write = ("[RESULTS]: MD5 Hash for: " + apk + " is: " + apk_md5_hash + "\n")
            file_txt_update.write(var_information_md5hash_write)

        sha1_hash = hashlib.sha1()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha1_hash.update(byte_block)
            apk_sha1_hash = sha1_hash.hexdigest()
            var_information_sha1hash_write = ("[RESULTS]: SHA1 Hash for: " + apk + " is: " + apk_sha1_hash + "\n")
            file_txt_update.write(var_information_sha1hash_write)

        sha256_hash = hashlib.sha256()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            apk_sha256_hash = sha256_hash.hexdigest()
            var_information_sha256hash_write = ("[RESULTS]: SHA256 Hash for: " + apk + " is: " + apk_sha256_hash + "\n")
            file_txt_update.write(var_information_sha256hash_write)

        sha512_hash = hashlib.sha512()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha512_hash.update(byte_block)
            apk_sha512_hash = sha512_hash.hexdigest()
            var_information_sha512hash_write = ("[RESULTS]: SHA512 Hash for: " + apk + " is: " + apk_sha512_hash + "\n")
            file_txt_update.write(var_information_sha512hash_write)

        try:        
            os.system(".\\win\\bin\\jadx.bat -d " + apk_decomp_directory + "\\" + apk + "_source " + apk_full_path)
        except:
            log_txt_update.write("[WARN]: Error Decompiling: " + apk_full_path + " with JADX \n")            
        
        var_ip_list_unscrubbed = []
        var_proto_list_unscrubbed = []

        try:
            with ZipFile(apk_full_path,"r") as var_apk_unzip:
                var_apk_unzip.extractall(apk_extract_directory + "\\")
        except:
            log_txt_update.write("[WARN]: Error Extracting: " + apk_full_path + "\n")
        
        var_path_to_android_xml = apk_extract_directory + "\\AndroidManifest.xml"
        var_cert_RSA_location = apk_extract_directory + "\\META-INF\\CERT.RSA"
        var_android_buildinfo_location = apk_extract_directory + "\\SEC-INF\\buildinfo.xml"
        


        ### Cleanup (Per APK) ###
        apk_move_cleanup_loc = apk_source_directory + "\\" + apk_with_extension
        try:
            shutil.move(apk_full_path, apk_move_cleanup_loc)
        except:
            log_txt_update.write("[WARN]: Error Moving APK: " + apk_full_path + " to: " + apk_move_cleanup_loc + "\n")
        file_txt_update.close()

if __name__ == "__main__":
   main(sys.argv[1:])
   
def easteregg():
	print "### ME MEME, YOU MEME, WE ALL MEME, FOR MOAR MEMES ###"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2584\u2584\u2584\u2584\u2584\u2584\u2584\u2584\u2584\u2584\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2588\u2588\u2580\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2580\u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2588\u2580\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2580\u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2584\u2591\u2591\u2591\u2591\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2588\u2588\u2588\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2591\u2591\u2580\u2580\u2588\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2588\u2584\u2588\u2588\u2580\u2584\u2591\u2591\u2591\u2591\u2591\u2584\u2588\u2588\u2588\u2584\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2580\u2580\u2580\u2588\u2588\u2580\u2591\u2591\u2591\u2591\u2591\u2584\u2584\u2584\u2591\u2591\u2580\u2588\u2591\u2591\u2591\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2584\u2580\u2591\u2591\u2591\u2591\u2584\u2580\u2591\u2584\u2591\u2591\u2588\u2584\u2588\u2588\u2580\u2584\u2591\u2591\u2591\u2591\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2588\u2591\u2591\u2591\u2591\u2580\u2591\u2591\u2591\u2588\u2591\u2591\u2591\u2580\u2580\u2580\u2580\u2580\u2591\u2591\u2591\u2591\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2588\u2584\u2591\u2591\u2591\u2591\u2591\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2580\u2591"
	print u"\u2591\u2591\u2591\u2591\u2591\u2591\u2588\u2580\u2591\u2591\u2591\u2591\u2580\u2580\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2588\u2588\u2588\u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591"
	print u"\u2591\u2591\u2591\u2584\u2584\u2591\u2580\u2591\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2580\u2591\u2591\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591"
	print u"\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2588\u2584\u2588\u2580\u2591\u2584\u2591\u2591\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2588\u2584\u2588\u2588\u2588\u2588\u2588\u2580\u2591\u2591\u2591"
	print u"\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2580\u2588\u2588\u2588\u2588\u2580\u2591\u2580\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584"
	print u"\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2580\u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"
	print u"\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2591\u2591\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"
	print u"\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2584\u2588\u2580\u2591\u2591\u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"
	print u"\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584\u2584\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2580\u2591\u2591\u2591\u2584\u2580\u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"
	print ""
