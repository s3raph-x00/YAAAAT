########################################################################################################################################
#################################################### Author:      s3raph                ################################################
#################################################### Purpose:     To Pass the Butter    ################################################
#################################################### Version:     .07153                ################################################
#################################################### Last Update: 20220815              ################################################
########################################################################################################################################

import os
import time
import subprocess
import shutil
import sys
import json
import getopt
import glob
import hashlib
import re
import base64
import platform
from zipfile import ZipFile
from struct import pack, unpack
from xml.sax.saxutils import escape

if sys.version_info >= (2, 7, 0) and sys.version_info < (3, 0, 0):
    import urlparse
if sys.version_info >= (3, 0, 0):
    import urllib.parse
    print("[ERROR]: Python 3 Not Supported At This Time.")
    sys.exit()

def func_fail_whale():
########################################################################################################################################
########################################################### FAIL WHALE FUNCTION ########################################################
########################################################################################################################################
    print(u"\u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2584\u2590\u2588\u2584\u2584\u2584\u2584\u2588\u258c")
    print(u"\u2588\u2588\u2588\u2588\u2588\u2588\u258c\u2584\u258c\u2584\u2590\u2590\u258c\u2588\u2588\u2588\u258c\u2580\u2580\u2588\u2588\u2580\u2580")
    print(u"\u2588\u2588\u2588\u2588\u2584\u2588\u258c\u2584\u258c\u2584\u2590\u2590\u258c\u2580\u2588\u2588\u2588\u2584\u2584\u2588\u258c")
    print(u"\u2584\u2584\u2584\u2584\u2584\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2580")
    time.sleep(.5) 
    print("[ERROR]: Error Occured")
    time.sleep(.3)
    print("[INFO]: Trying Process Again")
    time.sleep(.5)
    return

def func_hello():
########################################################################################################################################
########################################################### MUCH ASCII FUNCTION ########################################################
########################################################################################################################################
    print("")
    print(" @@@ @@@ @@@@@@@@ @@@@@@@       @@@@@@  @@@  @@@  @@@@@@  @@@@@@@ @@@  @@@ @@@@@@@@ @@@@@@@        @@@@@@  @@@  @@@ @@@@@@@  @@@@@@@   @@@@@@  @@@ @@@@@@@ ")
    print(" @@! !@@ @@!        @@!        @@!  @@@ @@!@!@@@ @@!  @@@   @@!   @@!  @@@ @@!      @@!  @@@      @@!  @@@ @@!@!@@@ @@!  @@@ @@!  @@@ @@!  @@@ @@! @@!  @@@")
    print("  !@!@!  @!!!:!     @!!        @!@!@!@! @!@@!!@! @!@  !@!   @!!   @!@!@!@! @!!!:!   @!@!!@!       @!@!@!@! @!@@!!@! @!@  !@! @!@!!@!  @!@  !@! !!@ @!@  !@!")
    print("   !!:   !!:        !!:        !!:  !!! !!:  !!! !!:  !!!   !!:   !!:  !!! !!:      !!: :!!       !!:  !!! !!:  !!! !!:  !!! !!: :!!  !!:  !!! !!: !!:  !!!")
    print("   .:    : :: :::    :          :   : : ::    :   : :. :     :     :   : : : :: ::: !:   : :       :   : : ::    :  :: :  :   :   : :  : :. :  :   :: :  : ")
    print("                                @@@@@@  @@@  @@@  @@@@@@  @@@   @@@ @@@  @@@@@@ @@@  @@@@@@       @@@@@@@  @@@@@@   @@@@@@  @@@    ")
    print("                               @@!  @@@ @@!@!@@@ @@!  @@@ @@!   @@! !@@ !@@     @@! !@@             @@!   @@!  @@@ @@!  @@@ @@!    ")
    print("                               @!@!@!@! @!@@!!@! @!@!@!@! @!!    !@!@!   !@@!!  !!@  !@@!!          @!!   @!@  !@! @!@  !@! @!!    ")
    print("                               !!:  !!! !!:  !!! !!:  !!! !!:     !!:       !:! !!:     !:!         !!:   !!:  !!! !!:  !!! !!:    ")
    print("                                :   : : ::    :   :   : : : ::.::.:    ::.: :  :   ::.: :           :     : :. :   : :. :  : ::.: :")
    print("")
    print("") 
    print("                                                         __..--"".          .""--..__                 ")#Credits For The ASCII Scythe Go To: David Palmer
    print("                                                   _..-``       ][\        /[]       ``-.._           ")
    print("                                               _.-`           __/\ \      / /\__           `-._       ")
    print("                                            .-`     __..---```    \ \    / /    ```---..__     `-.    ")
    print("                                          .`  _.--``               \ \  / /               ``--._  `.    ")
    print("                                         / .-`                      \ \/ /                      `-. \    ")
    print("                                        /.`                          \/ /                          `.\    ")
    print("                                       |`                            / /\                            `|    ")
    print("                               @@@@@@  @@@@@@@  @@@  @@@      @@@@@@@  @@@ @@@@@@@  @@@@@@@  @@@@@@@@ @@@@@@@ ")
    print("                              @@!  @@@ @@!  @@@ @@!  !@@      @@!  @@@ @@! @@!  @@@ @@!  @@@ @@!      @@!  @@@")
    print("                              @!@!@!@! @!@@!@!  @!@@!@!       @!@!!@!  !!@ @!@@!@!  @!@@!@!  @!!!:!   @!@!!@! ")
    print("                              !!:  !!! !!:      !!: :!!       !!: :!!  !!: !!:      !!:      !!:      !!: :!! ")
    print("                               :   : :  :        :   :::       :   : : :    :        :       : :: :::  :   : :")

def func_goodbye():
########################################################################################################################################
############################################################# SUCH END FUNCTION ########################################################
########################################################################################################################################
    print("")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$NN$$$$$$$NN$$$$N$N$NN$$$$$N$$$$$$$$NNN$$NN$$$$NNNNNNN$$$N$$$NNN$$$$$$N$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$NNV.....:.VN..........M..........F$$$$F:::*VNNV:::VMM*.....*MNMM.....*NNV...*N$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$N.........*M..........M..........MNNNN:....:MN:...*..........VMM......NN*....N$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$N....NN*..NN.....NM:..N....*NM:..NN$$NN*...IM*..**....MNNN:...MN....*$N$$..N$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$N......NMNNM....I..*NNM....I..INN$$$$N$N.......MV....IMNNN*...:M....N$N$...NN$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$NN.......NN........NMN........MN$$$$$N$N.....:NN.....NNN$N....V.....NNNN..MN$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$NNNM*.....MN....MF..NNN....M*..MN$$$$$$$N....VNNN....VNNNNM....N....N$$N...N$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$...NNN....M.....MNN...V....NNM...$$$$$$$N....NNNNV....MMMV....MN....NNNV..M$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$F.........*......................M$$$$$$*.....MNNNN:..........MMN.........:N$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$NVNM:..*MNMVVVVVVVFVVIIVVVVVVVVVIN$$$$$NMVVVVVN$$$$NNMV...*MNN$$$NNI...*MNN$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    print("$$$NNNNNNNNNNNNNN$$$NNNN$$NNNMN$$$$$$$NNNNNNNNNNNNNNNNNNNNN$$$$$NNNNNMNNNNNNNNNNNMMNNNNNNNNNNMNNNNNNNNNNNN$N$$$$$$$$$$$$$$NNNNNNN$$$NNNNNN$NNNNN$$$$$$$$$$$$$$")
    print("$$$N*.........M..........NNM....N$$$$*.........V..........N$$$$NNM.........MMV.........N:.....:......MN..............NNNF.........NM......N*....N$$$$$$$$$$$$$")
    print("$$$M....MM...VNM....M.....MV....NNNM.....MM....N....:MV...N$N$$N:....IMF...M.....MNF....M.....NM....MNN...FM....I....*N.....NNN....M*....NN*...MN$$$$$$$$$$$$$")
    print("$$$I.....MN**NN.....M....:*.....F$M.....NNNN..MI....M*.V.MNN$NM.....NNNN..V....VNNNN.....M....NM....MN...NN....MM:...V....*N$$N*...IN....M...MN$$$$$$$$$$$$$$$")
    print("$$$N.......MNNN..........*.......N.....M$$NNNNN........NNN$NNM:....NN$$NNN*....NN$$N.....M....N*....M...MNM.........VM....N$$$$*...M$V......NN$$$$$$$$$$$$$$$$")
    print("$$$$$M......VN........VM.........N....VN$$$$NNM....V...NNNNNNN....VNN$$NN$.....$NNNM....IM.............NNN....:*....*:...M$$$$N....MNN....*N$$$$$$$$$$$$$$$$$$")
    print("$N..MNNI.....M....M$NNM..........N....INNNNVNM.....MMM..VNNNNN....VNNNNFMN*....N$MM.....NN......M....:NNNM....NNM....M...N$$$$*...*NNI....NNV.:NNI..MMM..IN$$$")
    print("$*....M.....V.....N$$V....MNM.....*.....................MNNNNNF..........MM....VI.....*N$N....:NN..*INNNM*..........INV...MNM:...INN*.....N*....M....M....MN$$")
    print("$..........M......V$$.....NN......MF.......MV...........NN$$$$$M.......*NNNN*.......VN$$$N:...MNN..MN$$NV..........MN$NF:......VN$$N......NM...:M....M....NN$$")
    print("$$NN$$$$$$$NN$$$N$$$$$$N$NNNN$$NNN$$N$N$NNN$$NNNNNNNNNNN$$$$$$$NNNNNNNNN$$NNNNNNNNNNN$$$$NNNNNNN$N$$$$NN$$$$$$$$$NN$$$$$$$$$$$$$$$$$NN$$$N$$$NNNNNNNNN$NN$N$$$")
    print("")

def func_gu_st():
########################################################################################################################################
########################################################### GUCCI MODE FUNCTION ########################################################
########################################################################################################################################
    if arg_verbose_output == 1:
        if arg_gucci_output == 1:
            func_set_console_strobe()
            os.system('color 04')

def func_python_version_check():
########################################################################################################################################
########################################################## PYTHON CHECK FUNCTION #######################################################
########################################################################################################################################
    global var_python_version_info
    global var_python_version2_check
    global var_python_version3_check
    var_current_function = "func_python_version_check"
    
    if sys.version_info >= (2, 7, 0) and sys.version_info < (3, 0, 0):
        var_python_version2_check = "TRUE"
        var_python_version3_check = "FALSE"
        var_python_version_info = "2.7+"
        var_py_complete_flag = 1
    elif sys.version_info >= (3, 0, 0):
        var_python_version2_check = "FALSE"
        var_python_version3_check = "TRUE"
        var_python_version_info = "3.0+"  
        var_py_complete_flag = 1
    else:
        print("[ERROR]: Python Version Does Not Appear to Be Supported")
        print("[WARN]: Python 2.7+ or 3.1+ is a requirement")
        func_fail_whale()

def func_determine_operating_system():
########################################################################################################################################
####################################################### O/S DETERMINATION FUNCTION #####################################################
########################################################################################################################################
    var_current_function = "func_determine_operating_system"
    try:
        global var_OS_ver_A
        global var_OS_ver_B
        global var_OS_ver_C
        global var_OS_ver_D
        global var_OS_ver_E
        global var_OS_main_ver
        global var_PY_ver_A
        global var_PY_ver_B
        global var_PY_ver_C
        global var_sys_complete_flag
        
        var_OS_ver_A = platform.system()
        var_OS_ver_B = os.name
        var_OS_ver_C = sys.platform
        var_OS_ver_D = platform.platform()
        var_OS_ver_E = platform.processor()
        var_OS_main_ver = "O/S: " + platform.platform()
        var_PROC_model = "Processor: " + platform.processor()
        var_PY_ver_A = platform.python_version()
        var_PY_ver_B = sys.version
        var_PY_ver_C = sys.version_info
        var_sys_complete_flag = 1
    except:
        var_manual_error_code = 1
        print("[WARN]: Operating System Determination Failed")
        time.sleep(.5)
        func_fail_whale()

### Console/Error Text Color ###
def func_set_console_color_for_errors():
########################################################################################################################################
######################################################### CONSOLE COLOR FUNCTION #######################################################
########################################################################################################################################
    if var_manual_error_code == (0): ## This Means Normal Operation
        os.system('color 70') 
        return
    if var_manual_error_code == (1): ## This Means Major Error (Hard Fail)
        func_set_console_strobe()
        os.system('color 4F') 
        func_fail_whale()
    if var_manual_error_code == (2): ## This Means Minor Error (Attempting to Recover)
        func_fail_whale()
    else:
        print("Error")

def func_set_console_strobe():
########################################################################################################################################
############################################################ STROBE FUNCTION ###########################################################
########################################################################################################################################
    var_current_function = "func_set_console_strobe"    
    os.system('color 7C')
    time.sleep(.1)
    os.system('color C7')
    time.sleep(.1)
    os.system('color 7C') 
    time.sleep(.1)
    os.system('color C7')
    time.sleep(.1)
    os.system('color 7C')
    time.sleep(.1)

def func_global_var_declare():
########################################################################################################################################
######################################################## GLOBAL VARIABLE FUNCTION ######################################################
########################################################################################################################################
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

    var_ipv4_regex_pattern = "r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'"
    var_ipv6_regex_pattern = "r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'"
    var_phonenum_regex_pattern = "r'^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$')"
    possible_default_password_regex_pattern = "r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$')"
    possible_ssn_regex_pattern = "r'^(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}$')"
    possible_url_hiconf_regex_pattern = "r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)')"
    possible_url_lowconf_regex_pattern = "r'(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)')"
    possible_ftp_hiconf_regex_pattern = "r'ftps?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)')"
    possible_ssh_hiconf_regex_pattern = "r'ssh:\/\/(@\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b')"
    possible_bitcoinaddr_regex_pattern = "r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$')"
    possible_macaddr_regex_pattern = "r'^[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}$')"
    possible_email_regex_pattern = re.compile(r'(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))')

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
    global var_ip_list_unscrubbed
    global var_proto_list_unscrubbed

    var_ip_list_unscrubbed = []
    var_proto_list_unscrubbed = []

    ### Known File Locations For Rip ###

    global cert_content_extract_sub
    global cert_content_extract_serial
    global cert_content_extract_algorithm
    global cert_content_extract_notbefore
    global cert_content_extract_notafter

def func_apk_json_map():
########################################################################################################################################
######################################################## JSON-PYTHON DICTIONARY MAP ####################################################
########################################################################################################################################
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

def func_find_javahome():
########################################################################################################################################
############################################################ Find JDK Function #########################################################
########################################################################################################################################
    if 'JAVA_HOME' in os.environ:
        var_jdk_loc_1 = os.environ['JAVA_HOME']
        if "jdk" in var_jdk_loc_1:
            global var_jdk_keytool_location
            var_jdk_keytool_location = var_jdk_loc_1 + "\\bin\\keytool.exe"

def func_base64_decode(var_string_decode_req_base64):
########################################################################################################################################
########################################################## BASE-64 Decode Function #####################################################
########################################################################################################################################
    global var_base64_decode
    global var_decoded_base64
    if var_string_decode_req_base64:
        try:
            var_base64_decode = base64.b64decode(var_string_decode_req_base64)
            var_decoded_base64 = str(var_base64_decode)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[INFO]: Error Decoding Potential Base64 String: " + var_string_decode_req_base64 + "\n")
            if arg_verbose_output == 1:
                print("[INFO]: Error Decoding Potential Base64 String: " + var_string_decode_req_base64 + "\n")

def func_android_cert_pull():
########################################################################################################################################
####################################################### APK Certificate Rip Function ###################################################
########################################################################################################################################
    global var_path_to_android_xml
    global var_cert_RSA_location
    global var_android_buildinfo_location
    func_find_javahome()

    var_x_int = 0

    if var_jdk_keytool_location:
        try:
            var_keytool_command = '"\\" + var_jdk_keytool_location + " -printcert -file " + var_cert_RSA_location + " >> " + apk_results_directory + "\\" + apk + "_cert_keytool_out.txt" + "\\"'
            os.system(var_keytool_command)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Running Keytool against Certificate File Located At: " + var_cert_RSA_location + "\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Running Keytool against Certificate File Located At: " + var_cert_RSA_location)

    temp_certificate_keytxt_file = apk_results_directory + "\\" + apk + "_cert_keytool_out.txt"
    var_bool_keytxt_file = os.path.exists(temp_certificate_keytxt_file)
    if var_bool_keytxt_file:
        temp_certificate_txt_file_extract = open(temp_certificate_keytxt_file)
        for temp_certificate_txt_file_line in temp_certificate_txt_file_extract:
            temp_certificate_txt_file_line = temp_certificate_txt_file_line.rstrip('\n')
            cert_content_extract_serial = re.findall('number:(.*)', temp_certificate_txt_file_line)
            for var_each_extract_serial in cert_content_extract_serial:
                cert_unproc_txt_update.write("[Method KT]: APK Certificate Serial Number: " + var_each_extract_serial + "\n")
            cert_content_extract_owner = re.findall('Owner:(.*)', temp_certificate_txt_file_line)
            for var_each_extract_owner in cert_content_extract_owner:
                cert_unproc_txt_update.write("[Method KT]: APK Certificate Owner: " + var_each_extract_owner + "\n")
            cert_content_extract_md5 = re.findall(r'MD5:(.*)', temp_certificate_txt_file_line)
            for var_each_extract_md5 in cert_content_extract_md5:
                cert_unproc_txt_update.write("[Method KT]: APK Certificate MD5: " + var_each_extract_md5 + "\n")
            cert_content_extract_SHA1 = re.findall('SHA1:(.*)', temp_certificate_txt_file_line)
            for var_each_extract_SHA1 in cert_content_extract_SHA1:
                cert_unproc_txt_update.write("[Method KT]: APK Certificate SHA1: " + var_each_extract_SHA1 + "\n")
            cert_content_extract_SHA256 = re.findall('SHA256:(.*)', temp_certificate_txt_file_line)
            for var_each_extract_SHA256 in cert_content_extract_SHA256:
                cert_unproc_txt_update.write("[Method KT]: APK Certificate SHA256: " + var_each_extract_SHA256 + "\n")

    try:
        os.system(".\\win\\openssl.exe pkcs7 -inform DER -in " + var_cert_RSA_location + " -noout -print_certs -text" + " >> " + apk_results_directory + "\\" + apk + "_cert_meth_1.txt")
    except:
        if var_forensic_case_bool == 1:
            log_txt_update.write("[WARN]: [Method 1] Error Running OpenSSL against Certificate File Located At: " + var_cert_RSA_location + ", Trying [Method 2]\n")
        if arg_verbose_output == 1:
            print("[WARN]: [Method 1] Error Running OpenSSL against Certificate File Located At: " + var_cert_RSA_location + ", Trying [Method 2]")
    
    temp_certificate_txt_file = apk_results_directory + "\\" + apk + "_cert_meth_1.txt"
    if os.path.exists(temp_certificate_txt_file):
        temp_certificate_txt_file_extract = open(temp_certificate_txt_file)
        for temp_certificate_txt_file_line in temp_certificate_txt_file_extract:
            temp_certificate_txt_file_line = temp_certificate_txt_file_line.rstrip('\n')
            cert_content_extract_serial = re.findall('Number:(.*)', temp_certificate_txt_file_line)
            for var_each_cert_serial in cert_content_extract_serial:
                cert_unproc_txt_update.write("[Method 1]: APK Certificate Serial Number: " + var_each_cert_serial + "\n")
            cert_content_extract_subject = re.findall('Subject:(.*)', temp_certificate_txt_file_line)
            for var_each_cert_subject in cert_content_extract_subject:
                cert_unproc_txt_update.write("[Method 1]: APK Certificate Subject: " + var_each_cert_subject + "\n")
            cert_content_extract_sigalg = re.findall('Signature Algorithm:(.*)', temp_certificate_txt_file_line)
            for var_each_cert_sigalg in cert_content_extract_sigalg:
                cert_unproc_txt_update.write("[Method 1]: APK Certificate Signature Algorithm: " + var_each_cert_sigalg + "\n")

        try:
            rsa_cert_file_var_text = subprocess.check_output(".\\win\\openssl.exe pkcs7 -inform DER -in " + var_cert_RSA_location + " -noout -print_certs -text")
            var_cert_content = []
            for line_rsa_cert_file_var_text in rsa_cert_file_var_text:
                var_cert_content.append(line_rsa_cert_file_var_text.rstrip())

            var_cert_content_munged = "".join(str(x) for x in var_cert_content)

            cert_content_extract_subject = re.findall('Subject:(.*?)SubjectPublicKeyInfo', var_cert_content_munged)
            cert_content_extract_serial = re.findall('SerialNumber:(.*?)SignatureAlgorithm:', var_cert_content_munged)
            cert_content_extract_algorithm = re.findall('PublicKeyAlgorithm:(.*?)EncryptionRSAPublicKey:', var_cert_content_munged)
            cert_content_extract_notbefore = re.findall('ValidityNotBefore:(.*?)NotAfter:', var_cert_content_munged)
            cert_content_extract_notafter = re.findall('NotAfter:(.*?)Subject:', var_cert_content_munged)
            cert_unproc_txt_update.write("[Method 2]: APK Certificate Serial: " + cert_content_extract_serial + "\n")
            cert_unproc_txt_update.write("[Method 2]: APK Certificate Subject: " + cert_content_extract_subject + "\n")
            cert_unproc_txt_update.write("[Method 2]: APK Certificate Algorithm: " + cert_content_extract_algorithm + "\n")
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Running OpenSSL against Certificate File Located At: " + var_cert_RSA_location + " with [Method 2]\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Running OpenSSL against Certificate File Located At: " + var_cert_RSA_location + " with [Method 2]")

def func_large_scale_regex():
########################################################################################################################################
########################################################## REGEX PER LINE FUNCTION #####################################################
########################################################################################################################################

    global var_url_high_count
    global var_url_med_count
    global var_url_low_count
    global var_IPv4_count
    global var_IPv6_low_count
    global var_IPv6_high_count
    global var_search_hits
    global var_email_count

    var_url_high_count = 0
    var_url_med_count = 0
    var_url_low_count = 0
    var_IPv4_count = 0
    var_IPv6_low_count = 0
    var_IPv6_high_count = 0
    var_search_hits = 0
    var_email_count = 0
        
    if arg_verbose_output == 1:
        print("[REGEX] #################################### RUNNING REGEX AGAINST JADX OUTPUT ####################################")
        print("")
    for var_path, var_directory, var_files in os.walk(os.path.abspath(apk_decomp_directory)):
        for var_each_file in var_files:
            var_ref_filepath = os.path.join(var_path, var_each_file)
            if os.path.isfile(var_ref_filepath):
                var_directory_file_object = open(var_ref_filepath)
                for var_directory_file_object_line in var_directory_file_object:
                    apk_content_extract_ipv4 = re.findall(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', var_directory_file_object_line)
                    apk_content_extract_ipv4_tup_len = len(apk_content_extract_ipv4)
                    var_chain_count = 0
                    if apk_content_extract_ipv4:
                        var_IPv4_count = var_IPv4_count + 1
                        if arg_verbose_output == 1:
                            print("[IPV4]: SOURCE FILE: " + var_ref_filepath)
                            print("[IPV4]: SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())
                        ip_extract_write_txt_update.write("[URL-MED] SOURCE FILE: " + var_ref_filepath + "\n")
                        ip_extract_write_txt_update.write("[URL-MED] SOURCE LINE: " + var_directory_file_object_line.strip('\n') + "\n")                    
                        while var_chain_count < apk_content_extract_ipv4_tup_len:
                            if apk_content_extract_ipv4[var_chain_count]:
                                if arg_debug_output == 1:
                                    ipv6_extract_write_txt_up.write("[IPV4]: Potential IPv4 Address Found: " + apk_content_extract_ipv4[var_chain_count] + "\n")
                                    if arg_verbose_output == 1:
                                        print("[IPV4]: Potential IPv4 Address Found: " + apk_content_extract_ipv4[var_chain_count])
                                var_chain_count = var_chain_count + 1
                            else:
                                var_chain_count = var_chain_count + 1

                    var_med_IPv6_conf_check = 0
                    apk_content_extract_ipv6_test = re.findall(r'^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$', var_directory_file_object_line)
                    var_chain_count = 0
                    if apk_content_extract_ipv6_test:
                        var_IPv6_high_count = var_IPv6_high_count + 1
                        if arg_verbose_output == 1:
                            print("[IPv6-MOD]: SOURCE FILE: " + var_ref_filepath)
                            print("[IPv6-MOD]: SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())
                        while var_chain_count < apk_content_extract_ipv6_len:
                            if apk_content_extract_ipv6[var_chain_count]:
                                var_med_IPv6_conf_check = 1
                                var_tmp_string = apk_content_extract_ipv6[var_chain_count]
                                var_tmp_string_len = len(var_tmp_string)
                                if var_tmp_string_len != 0:
                                    var_chain_v2_count = 0
                                    while var_chain_v2_count < var_tmp_string_len:
                                        if var_tmp_string[var_chain_v2_count]:
                                            var_tmp_string_cln = var_tmp_string[var_chain_v2_count]
                                            if arg_debug_output == 1:
                                                ipv6_extract_write_txt_up.write("[IPV6-MOD]: REGEX HIT(S): " + var_tmp_string_cln + "\n")
                                                if arg_verbose_output == 1:
                                                    print("[IPV6-MOD]: REGEX HIT(S)" + var_tmp_string_cln)
                                            var_chain_v2_count = var_chain_v2_count + 1
                                        else:
                                            var_chain_v2_count = var_chain_v2_count + 1
                                    else:
                                        null_var = 0
                                var_chain_count = var_chain_count + 1
                            else:
                                var_chain_count = var_chain_count + 1

                    ### NEEDS POST REGEX CHECK ###
                    if var_med_IPv6_conf_check == 0:
                        apk_content_extract_ipv6 = re.findall(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))', var_directory_file_object_line)
                        apk_content_extract_ipv6_len = len(apk_content_extract_ipv6)
                        var_chain_count = 0
                        if apk_content_extract_ipv6:
                            var_IPv6_low_count = var_IPv6_low_count + 1
                            if arg_verbose_output == 1:
                                print("[IPv6-LOW]: SOURCE FILE: " + var_ref_filepath)
                                print("[IPv6-LOW]: SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())
                            ipv6_extract_write_txt_up.write("[IPv6-LOW]: SOURCE FILE: " + var_ref_filepath + "\n")
                            ipv6_extract_write_txt_up.write("[IPv6-LOW]: SOURCE LINE: " + var_directory_file_object_line.strip('\n') + "\n")         
                            while var_chain_count < apk_content_extract_ipv6_len:
                                if apk_content_extract_ipv6[var_chain_count]:
                                    var_tmp_string = apk_content_extract_ipv6[var_chain_count]
                                    var_tmp_string_len = len(var_tmp_string)
                                    if var_tmp_string_len != 0:
                                        var_chain_v2_count = 0
                                        while var_chain_v2_count < var_tmp_string_len:
                                            if var_tmp_string[var_chain_v2_count]:
                                                var_tmp_string_cln = var_tmp_string[var_chain_v2_count]
                                                if arg_debug_output == 1:
                                                    ipv6_extract_write_txt_up.write("[IPV6-LOW]: REGEX HIT(S)" + var_tmp_string_cln + "\n")
                                                    if arg_verbose_output == 1:
                                                        print("[IPV6-LOW]: REGEX HIT(S)" + var_tmp_string_cln)
                                                var_chain_v2_count = var_chain_v2_count + 1
                                            else:
                                                var_chain_v2_count = var_chain_v2_count + 1
                                        else:
                                            null_var = 0
                                    var_chain_count = var_chain_count + 1
                                else:
                                    var_chain_count = var_chain_count + 1
                    else:
                        if arg_debug_output == 1:
                            if arg_verbose_output == 1:
                                print("IPV6-LOW]: Already Matched on IPV6-MED] Regex. Skipping This Check.")
                    
                    var_high_conf_check = 0
                    apk_content_extract_hiconf_url = re.findall(r"^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$", var_directory_file_object_line)
                    apk_content_extract_hiconf_len = len(apk_content_extract_hiconf_url)
                    var_chain_count = 0
                    if apk_content_extract_hiconf_url:
                        var_high_conf_check = 1
                        var_url_high_count = var_url_high_count + 1
                        if arg_verbose_output == 1:
                            print("[URL-HI]:   SOURCE FILE: " + var_ref_filepath)
                            print("[URL-HI]:   SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())
                        hi_conf_URL_extract_write_txt_up.write("[URL-HI]:   SOURCE FILE: " + var_ref_filepath + "\n")
                        hi_conf_URL_extract_write_txt_up.write("[URL-HI]:   SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip() + "\n")
                        while var_chain_count < apk_content_extract_hiconf_len:
                            if apk_content_extract_hiconf_url[var_chain_count]:
                                var_tmp_string = apk_content_extract_hiconf_url[var_chain_count]
                                var_tmp_string_len = len(var_tmp_string)
                                if var_tmp_string_len != 0:
                                    var_chain_v2_count = 0
                                    while var_chain_v2_count < var_tmp_string_len:
                                        if var_tmp_string[var_chain_v2_count]:
                                            var_tmp_string_cln = var_tmp_string[var_chain_v2_count]
                                            if arg_debug_output == 1:
                                                hi_conf_URL_extract_write_txt_up.write("[URL-HI]:   REGEX HIT(S): " + var_tmp_string_cln + "\n")
                                                if arg_verbose_output == 1:
                                                    print("[URL-HI]:   REGEX HIT(S): " + var_tmp_string_cln)
                                            var_chain_v2_count = var_chain_v2_count + 1
                                        else:
                                            var_chain_v2_count = var_chain_v2_count + 1
                                    else:
                                        null_var = 0
                                var_chain_count = var_chain_count + 1

                    var_med_conf_check = 1
                    if var_high_conf_check == 0:
                    ### MOSTLY OK WITH CURRENT REGEX ###                    
                        apk_content_extract_loconf_url = re.findall(r'https:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)', var_directory_file_object_line)
                        apk_content_extract_loconf_len = len(apk_content_extract_loconf_url)
                        var_chain_count = 0
                        if apk_content_extract_loconf_url:
                            var_med_conf_check = 1
                            var_url_med_count = var_url_med_count + 1
                            if arg_verbose_output == 1:
                                print("[URL-MED]:  SOURCE FILE: " + var_ref_filepath)
                                print("[URL-MED]:  SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())
                            med_conf_URL_extract_write_txt_up.write("[URL-MED]:  SOURCE FILE: " + var_ref_filepath + "\n")
                            med_conf_URL_extract_write_txt_up.write("[URL-MED]:  SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip() + "\n")
                            while var_chain_count < apk_content_extract_loconf_len:
                                if apk_content_extract_loconf_url[var_chain_count]:
                                    var_tmp_string = apk_content_extract_loconf_url[var_chain_count]
                                    var_tmp_string_len = len(var_tmp_string)
                                    if var_tmp_string_len != 0:
                                        var_chain_v2_count = 0
                                        while var_chain_v2_count < var_tmp_string_len:
                                            if var_tmp_string[var_chain_v2_count]:
                                                var_tmp_string_cln = var_tmp_string[var_chain_v2_count]
                                                if arg_debug_output == 1:
                                                    med_conf_URL_extract_write_txt_up.write("[URL-MED]:  REGEX HIT(S): " + var_tmp_string_cln + "\n")
                                                    if arg_verbose_output == 1:
                                                        print("[URL-MED]:  REGEX HIT(S): " + var_tmp_string_cln)
                                                var_chain_v2_count = var_chain_v2_count + 1
                                            else:
                                                var_chain_v2_count = var_chain_v2_count + 1
                                        else:
                                            null_var = 0
                                    var_chain_count = var_chain_count + 1
                                else:
                                    var_chain_count = var_chain_count + 1
                    else:
                        if arg_debug_output == 1:
                            if arg_verbose_output == 1:
                                print("[URL-MED]:  Already Matched on [URL-HI] Regex. Skipping This Check.")

                    if var_med_conf_check == 0:
                        if var_high_conf_check == 0:
                            ### MOSTLY OK WITH CURRENT REGEX ###                    
                                apk_content_extract_lowconf_url = re.findall(r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$', var_directory_file_object_line)
                                apk_content_extract_lowconf_len = len(apk_content_extract_lowconf_url)
                                var_chain_count = 0
                                if apk_content_extract_lowconf_url:
                                    var_url_low_count = var_url_low_count + 1
                                    if arg_verbose_output == 1:
                                        print("[URL-LOW]:  SOURCE FILE: " + var_ref_filepath)
                                        print("[URL-LOW]:  SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())
                                    low_conf_URL_extract_write_txt_up.write("[URL-LOW]:  SOURCE FILE: " + var_ref_filepath + "\n")
                                    low_conf_URL_extract_write_txt_up.write("[URL-LOW]:  SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip() + "\n")
                                    while var_chain_count < apk_content_extract_lowconf_len:
                                        if apk_content_extract_lowconf_url[var_chain_count]:
                                            var_tmp_string = apk_content_extract_lowconf_url[var_chain_count]
                                            var_tmp_string_len = len(var_tmp_string)
                                            if var_tmp_string_len != 0:
                                                var_chain_v2_count = 0
                                                while var_chain_v2_count < var_tmp_string_len:
                                                    if var_tmp_string[var_chain_v2_count]:
                                                        var_tmp_string_cln = var_tmp_string[var_chain_v2_count]
                                                        if arg_debug_output == 1:
                                                            low_conf_URL_extract_write_txt_up.write("[URL-LOW]:  REGEX HIT(S): " + var_tmp_string_cln + "\n")
                                                            if arg_verbose_output == 1:
                                                                print("[URL-LOW]:  REGEX HIT(S): " + var_tmp_string_cln)
                                                        var_chain_v2_count = var_chain_v2_count + 1
                                                    else:
                                                        var_chain_v2_count = var_chain_v2_count + 1
                                                else:
                                                    null_var = 0
                                            var_chain_count = var_chain_count + 1
                                        else:
                                            var_chain_count = var_chain_count + 1
                        else:
                            if arg_debug_output == 1:
                                if arg_verbose_output == 1:
                                    print("[URL-LOW]:  Already Matched on [URL-HI] Regex. Skipping This Check.")
                    else:
                        if arg_debug_output == 1:
                            if arg_verbose_output == 1:
                                print("[URL-LOW]:  Already Matched on [URL-MED] Regex. Skipping This Check.")

                    apk_content_extract_email = re.findall(r'(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))', var_directory_file_object_line)
                    apk_content_extract_email_len = len(apk_content_extract_email)
                    var_chain_count = 0
                    if apk_content_extract_email:
                        var_email_count = var_email_count + 1
                        if arg_verbose_output == 1:
                            print("[EMAIL]:    SOURCE FILE: " + var_ref_filepath)
                            print("[EMAIL]:    SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())
                        email_extract_write_txt_up.write("[EMAIL]:    SOURCE FILE: " + var_ref_filepath + "\n")
                        email_extract_write_txt_up.write("[EMAIL]:    SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip() + "\n")
                        while var_chain_count < apk_content_extract_email_len:   
                            if apk_content_extract_email[var_chain_count]:     
                                var_tmp_string = apk_content_extract_email[var_chain_count]
                                var_tmp_string_len = len(var_tmp_string)                            
                                if var_tmp_string_len != 0:
                                    var_chain_v2_count = 0
                                    while var_chain_v2_count < var_tmp_string_len:
                                        if var_tmp_string[var_chain_v2_count]:
                                            var_tmp_string_cln = var_tmp_string[var_chain_v2_count]
                                            if arg_debug_output == 1:
                                                email_extract_write_txt_up.write("[EMAIL]:    REGEX HIT(S): " + var_tmp_string_cln + "\n")
                                                if arg_verbose_output == 1:
                                                    print("[EMAIL]:    REGEX HIT(S): " + var_tmp_string_cln)
                                            var_chain_v2_count = var_chain_v2_count + 1
                                        else:
                                            var_chain_v2_count = var_chain_v2_count + 1
                                    else:
                                        null_var = 0
                                var_chain_count = var_chain_count + 1
                            else:
                                var_chain_count = var_chain_count + 1

                    if arg_custom_search == 1:
                        if arg_string_search.lower() in var_directory_file_object_line.lower():
                            var_search_hits = var_search_hits + 1
                            custom_search_write_up.write("[SEARCH]:   SOURCE FILE: " + var_ref_filepath + "\n")
                            custom_search_write_up.write("[SEARCH]:   SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip() + "\n")                                 
                            if arg_verbose_output == 1:
                                print("[SEARCH]:   SOURCE FILE: " + var_ref_filepath)
                                print("[SEARCH]:   SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())    

                    if arg_custom_search == 2:
                        with open(arg_string_file_search,"r") as var_file_search_strings_file:
                            for var_file_search_string_line in var_file_search_strings_file:
                                if var_file_search_string_line.lower().strip('\n') in var_directory_file_object_line.lower():
                                    var_search_hits = var_search_hits + 1
                                    custom_search_write_up.write("[SEARCH]:   SOURCE FILE: " + var_ref_filepath + "\n")
                                    custom_search_write_up.write("[SEARCH]:   SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip() + "\n") 
                                    if arg_verbose_output == 1:
                                        print("[SEARCH]:   SOURCE FILE: " + var_ref_filepath)
                                        print("[SEARCH]:   SOURCE WORD: " + var_file_search_string_line.lower().strip('\n'))
                                        print("[SEARCH]:   SOURCE LINE: " + var_directory_file_object_line.strip('\n').strip())        
                                    if arg_debug_output == 1:
                                        custom_search_write_up.write("[SEARCH]:   SOURCE HIT:  " + var_file_search_string_line.strip('\n') + "\n") 
                                        if arg_verbose_output == 1:
                                            print("[SEARCH]:   SOURCE HIT:  " + var_file_search_string_line.strip('\n'))
                            
def func_clean_up():
########################################################################################################################################
######################################################### Post-Run Clean Up Function ###################################################
########################################################################################################################################
    if var_forensic_case_bool == 1:
        log_txt_update.close()
    #cert_unproc_txt_update.close()
    os.system('color 07')
    func_goodbye()

def func_initial_logging():
########################################################################################################################################
########################################################## Inital Log File Creation ####################################################
########################################################################################################################################
    if var_forensic_case_bool == 1:
        case_log_file_txt = var_case_delivery_directory + "\\log.txt"
        global log_txt_update
        log_txt_update = open(case_log_file_txt, "a")
        log_txt_update.write("--- YAAAAT APK Ripper ---\n")
        log_txt_update.write("[LOG]: Tool Started on: " + timestr_case + " at " + timestr_dir + "\n")  

def function_statistic_write():
########################################################################################################################################
######################################################### APK Extraction Statistics ####################################################
########################################################################################################################################

    var_url_high_count_str = str(var_url_high_count)
    var_url_med_count_str = str(var_url_med_count)
    var_url_low_count_str = str(var_url_low_count)
    var_IPv6_high_count_str = str(var_IPv6_high_count)
    var_IPv6_low_count_str = str(var_IPv6_low_count)
    var_IPv4_count_str = str(var_IPv4_count)
    var_email_count_str = str(var_email_count)
    var_embed_file_hits_str = str(var_embed_file_hits)
    var_search_hits_str = str(var_search_hits)
    
    count_stats_write_txt_up.write("[URL-HIGH]  Count: " + var_url_high_count_str + "\n")
    count_stats_write_txt_up.write("[URL-MED]   Count: " + var_url_med_count_str + "\n")
    count_stats_write_txt_up.write("[URL-LOW]   Count: " + var_url_low_count_str + "\n")
    count_stats_write_txt_up.write("[IPv6-HIGH] Count: " + var_IPv6_high_count_str + "\n")
    count_stats_write_txt_up.write("[IPv6-LOW]  Count: " + var_IPv6_low_count_str + "\n")
    count_stats_write_txt_up.write("[IPv4]      Count: " + var_IPv4_count_str + "\n")
    count_stats_write_txt_up.write("[EMAIL]     Count: " + var_email_count_str + "\n")
    count_stats_write_txt_up.write("[EMAIL]     Count: " + var_embed_file_hits_str + "\n")
    count_stats_write_txt_up.write("[SEARCH]    Count: " + var_search_hits_str + "\n")
    
    if arg_verbose_output == 1:
        print("[URL-HIGH]  Count: " + var_url_high_count_str)
        print("[URL-MED]   Count: " + var_url_med_count_str)
        print("[URL-LOW]   Count: " + var_url_low_count_str)
        print("[IPv6-HIGH] Count: " + var_IPv6_high_count_str)
        print("[IPv6-LOW]  Count: " + var_IPv6_low_count_str)
        print("[IPv4]      Count: " + var_IPv4_count_str)
        print("[EMAIL]     Count: " + var_email_count_str)
        print("[EMBEDFILE] Count: " + var_embed_file_hits_str)
        print("[SEARCH]    Count: " + var_search_hits_str)

def func_permission_checks():
########################################################################################################################################
###################################################### APK Manifest Permission Function ################################################
########################################################################################################################################
    global var_manifest_location
    global permission_check_manifest_text
    var_manifest_location = apk_extract_directory + "\\AndroidManifest.xml"
    if os.path.exists(var_manifest_location):
        try:        
            if arg_verbose_output == 1:
                print("")
                print("[MANIFEST] ################################# RUNNING STRINGS AGAINST JADX OUTPUT ##################################")
            os.system(".\\win\\strings.exe /accepteula " + var_manifest_location + " >> " + apk_results_directory + "\\" + apk + "_manifest_tmp_str.txt")
        except:            
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Running Strings against Manifest File Located At: " + var_manifest_location + "\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Running Strings against Manifest File Located At: " + var_manifest_location + "\n")   
    else:
        if var_forensic_case_bool == 1:
            log_txt_update.write("[WARN]: Manifest File Was Not Located At: " + var_manifest_location + "\n") 
        if arg_verbose_output == 1:
            print("[WARN]: Manifest File Was Not Located At: " + var_manifest_location + "\n") 

    temp_manifest_temp_file = apk_results_directory + "\\" + apk + "_manifest_tmp_str.txt"
    if os.path.exists(temp_manifest_temp_file):
        temp_manifest_file_extract = open(temp_manifest_temp_file)
        for temp_manifest_txt_file_line in temp_manifest_file_extract:
            temp_manifest_txt_file_line = temp_manifest_txt_file_line.rstrip('\n')
            mani_content_extract_permission = re.findall('android.permission.(.*)', temp_manifest_txt_file_line)
            for var_each_mani_permission in mani_content_extract_permission:
                mani_unproc_write_txt_update.write("[MANIFEST]: APK Permission Found: " + var_each_mani_permission + "\n")        
            mani_content_extract_permission = re.findall('android.hardware.(.*)', temp_manifest_txt_file_line)
            for var_each_mani_permission in mani_content_extract_permission:
                mani_unproc_write_txt_update.write("[MANIFEST]: APK Hardware Reference Found: " + var_each_mani_permission + "\n")       

def func_hash_all_files():
########################################################################################################################################
####################################################### Hash Extracted Files Function ##################################################
########################################################################################################################################
    global var_embed_file_hits
    var_embed_file_hits = 0
    for var_path, var_directory, var_files in os.walk(os.path.abspath(apk_decomp_directory)):
        for var_each_file in var_files:
            var_embed_file_hits = var_embed_file_hits + 1
            var_ref_filepath = os.path.join(var_path, var_each_file)
            if os.path.isfile(var_ref_filepath):
                md5_hash = hashlib.md5()
                with open(var_ref_filepath,"rb") as f:
                    for byte_block in iter(lambda: f.read(4096),b""):
                        md5_hash.update(byte_block)
                    file_md5_hash = md5_hash.hexdigest()
                    var_information_md5hash_write = ("[RESULTS]: MD5 Hash for: " + var_each_file + " is: " + file_md5_hash + "\n")
                    file_hashes_post_zip_extract_update.write(var_information_md5hash_write)

                sha1_hash = hashlib.sha1()
                with open(var_ref_filepath,"rb") as f:
                    for byte_block in iter(lambda: f.read(4096),b""):
                        sha1_hash.update(byte_block)
                    file_sha1_hash = sha1_hash.hexdigest()
                    var_information_sha1hash_write = ("[RESULTS]: SHA1 Hash for: " + var_each_file + " is: " + file_sha1_hash + "\n")
                    file_hashes_post_zip_extract_update.write(var_information_sha1hash_write)

                sha256_hash = hashlib.sha256()
                with open(var_ref_filepath,"rb") as f:
                    for byte_block in iter(lambda: f.read(4096),b""):
                        sha256_hash.update(byte_block)
                    file_sha256_hash = sha256_hash.hexdigest()
                    var_information_sha256hash_write = ("[RESULTS]: SHA256 Hash for: " + var_each_file + " is: " + file_sha256_hash + "\n")
                    file_hashes_post_zip_extract_update.write(var_information_sha256hash_write)

                sha512_hash = hashlib.sha512()
                with open(var_ref_filepath,"rb") as f:
                    for byte_block in iter(lambda: f.read(4096),b""):
                        sha512_hash.update(byte_block)
                    file_sha512_hash = sha512_hash.hexdigest()
                    var_information_sha512hash_write = ("[RESULTS]: SHA512 Hash for: " + var_each_file + " is: " + file_sha512_hash + "\n")
                    file_hashes_post_zip_extract_update.write(var_information_sha512hash_write)

def main(argv):
########################################################################################################################################
######################################################## Global Variable Definitions ###################################################
########################################################################################################################################
    global log_txt_update
    global case_log_file_txt
    global var_manual_error_code
    global inputdirectory
    global var_case_delivery_directory
    global arg_autopsy_plugin
    global arg_verbose_output
    global arg_gucci_output
    global var_forensic_case_bool
    global timestr_dir
    global timestr_case
    global var_output_directory
    global apk
    global arg_debug_output
    global arg_string_search
    global arg_string_file_search
    global arg_custom_search
    global var_sys_complete_flag
    global var_py_complete_flag
    global var_yara_flag

    timestr_dir = time.strftime("%H-%M-%S")
    timestr_case = time.strftime("%Y-%m-%d")
    inputdirectory_var = ''
    var_output_directory = ''
    arg_autopsy_plugin = 0
    arg_verbose_output = 0
    arg_gucci_output = 0
    var_forensic_case_bool = 0
    arg_debug_output = 0
    arg_custom_search = 0
    arg_string_search = ""
    arg_string_file_search = ""
    var_sys_complete_flag = 0
    var_py_complete_flag = 0
    var_yara_flag = 0
    
    global var_current_function
    var_current_function = "func_main"

########################################################################################################################################
############################################################### STAGE SETTING ##########################################################
########################################################################################################################################

    os.system('cls' if os.name == 'nt' else 'clear')
    func_hello()

########################################################################################################################################
############################################################## HELP AND ARGUMENT #######################################################
########################################################################################################################################

    try:
        opts, args = getopt.getopt(argv,"hacblrfgyvS:s:o:i:",["idir="])
    except getopt.GetoptError:
        var_manual_error_code = (1)
        func_fail_whale()
        print("YAAAAT_apk_ripper.py -i <Directory_To_Scan_For_APKs>")
        print("Optional Arguments:  -v (For Verbose Output) -a (RTFC)")
        print("                     -l (Forensic Case)")
        print("                     -f (Fix My Terminal Color x.x)")
        print("                     -r (Show REGEX Debug Output)")
        print("                     -s (Search for String) <From CLI>")
        print("                     -S (Search for Strings) <From File>")
        print("                     -y (Search with Yara)")
        os.system('color 07')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("YAAAAT_apk_ripper.py -i <Directory_To_Scan_For_APKs>")
            print("Optional Arguments:  -v (For Verbose Output) -a (RTFC)")
            print("                     -l (Forensic Case Logging)")
            print("                     -f (Fix My Terminal Color x.x)")
            print("                     -r (Show REGEX Debug Output)")
            print("                     -s (Search for String) <From CLI>")
            print("                     -S (Search for Strings) <From File>")
            print("                     -y (Search with Yara)")
            os.system('color 07')
            sys.exit()
        if opt == '-f':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    Terminal Color Black                        ###
            ### Arg:     -f                                          ###
            ### Info:    This Argument is Used To Fix Terminal Color ###
            ###          After Crashing/Ending This Application      ###
            ###          Ungracefully in Gucci Mode.                 ###
            ### Note:    In Any Color, As Long as You Want It Black  ###
            ### Default: Disabled                                    ###
            ############################################################
            os.system('color 07')
            sys.exit()
        if opt == '-a':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    Post-Autopsy File Normalization             ###
            ### Arg:     -a                                          ###
            ### Info:    This Argument is Used To Remove Characters  ###
            ###          Prepended To Filename During The Autopsy    ###
            ###          Extraction Process.                         ###
            ### Default: Disabled                                    ###
            ############################################################
            arg_autopsy_plugin = 1
        if opt == '-v':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    Verbosity                                   ###
            ### Arg:     -v                                          ###
            ### Info:    Sets the Verbosity to Debug                 ###
            ### Default: Silent                                      ###
            ############################################################
            arg_verbose_output = 1
        if opt == '-g':
            ############################################################
            ###              [Absolutely Not Required]               ###
            ### Name:    Gucci Mode                                  ###
            ### Arg:     -g                                          ###
            ### Info:    Original G. <! Epilepsy Warning !>          ###
            ### Note:    Why the F*** Did I Code This?               ###
            ### Default: Disabled                                    ###
            ############################################################
            arg_gucci_output = 1
        if opt == '-l':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    Forensic Case Logging                       ###
            ### Arg:     -l                                          ###
            ### Info:    Outputs Verbose Logging And Forensic System ###
            ###          Information To Log File in Output Directory.### 
            ### Default: Disabled                                    ###
            ############################################################
            var_forensic_case_bool = 1
        if opt == '-o':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    Output Directory                            ###
            ### Arg:     -o                                          ###
            ### Info:    Sets the Output Directory If Defined.       ###
            ### Default: <Input_Directory>                           ###
            ############################################################
            var_output_directory = arg
        if opt == '-r':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    REGEX Debug Output                          ###
            ### Arg:     -r                                          ###
            ### Info:    Outputs what was REGEX'd on for development.###
            ### Default: Disabled                                    ###
            ############################################################
            arg_debug_output = 1
        if opt == '-s':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    String Search <CLI>                         ###
            ### Arg:     -s                                          ###
            ### Info:    Search For A Single String in Output of     ###
            ###          decompiled JADX output.                     ###
            ### Default: ""                                          ###
            ############################################################
            arg_custom_search = 1
            arg_string_search = arg
        if opt == '-y':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    Yara Search                                 ###
            ### Arg:     -y                                          ###
            ### Info:    Uses rules located in ./yara/ to flag on    ###
            ###          specified alerts.                           ###
            ### Default: Disabled                                    ###
            ############################################################
            var_yara_flag = 1
        if opt == '-S':
            ############################################################
            ###                     [Not Required]                   ###
            ### Name:    String Search <File>                        ###
            ### Arg:     -S                                          ###
            ### Info:    Search For Strings Contained in Specified   ###
            ###          text file against the Output of decompiled  ###
            ###          JADX output.                                ###
            ### Default: ""                                          ###
            ############################################################
            if not os.path.isfile(arg):
                func_fail_whale()
                print("Search String File Not Found: " + arg)
                sys.exit()
            arg_string_file_search = arg
            arg_custom_search = 2
        elif opt in ("-i", "--idir"):
            ############################################################
            ###                       [Required]                     ###
            ### Name:    Input Directory                             ###
            ### Arg:     -i                                          ###
            ### Info:    Sets the Input Directory.                   ###
            ### Default: <No Value>                                  ###
            ############################################################
            inputdirectory_var = arg

    if not inputdirectory_var:
        print("")
        print("[ERROR]: MUST SPECIFY DIRECTORY")
        print("")
        print("YAAAAT_apk_ripper.py -i <Directory_To_Scan_For_APKs>")
        print("Optional Arguments:  -v (For Verbose Output) -a (RTFC)")
        print("                     -l (Forensic Case)")
        print("                     -f (Fix My Terminal Color x.x)")
        print("                     -r (Show REGEX Debug Output)")
        print("                     -s (Search for String) <From CLI>")
        print("                     -S (Search for Strings) <From File>")
        print("                     -y (Search with Yara)")
        os.system('color 07')
        sys.exit()

    inputdirectory_var = inputdirectory_var.replace('\"', '') + "\\"	
    func_gu_st()
    func_global_var_declare()
    func_python_version_check()

########################################################################################################################################
########################################################## CASE DIRECTORY CREATION #####################################################
########################################################################################################################################
    
    print("########################################################################################################################################")
    print("######################################################## RIPPER STARTED AT: " + timestr_dir + " ###################################################")
    print("########################################################################################################################################")
    print("")

    inputdirectory = os.path.dirname(inputdirectory_var)
    if var_forensic_case_bool == 1:
        var_case_delivery_directory = inputdirectory + "\\" + timestr_case + "_case_info"
        if os.path.exists(var_case_delivery_directory):
            print("[INFO]: Case Directory: " + var_case_delivery_directory + " Already Exists")
        else:
            try:
                os.mkdir(var_case_delivery_directory)
            except:
                print("[WARN]: Error Making Main Case Directory: " + var_case_delivery_directory)
        func_initial_logging()
        func_determine_operating_system()

    if var_sys_complete_flag == 1:
        if var_forensic_case_bool == 1:
            log_txt_update.write("[SYS]: O/S Version is: " + var_OS_main_ver + "\n")
            log_txt_update.write("[SYS]: Python Version is: " + var_PY_ver_A + "\n")
            log_txt_update.write("[SYS]: Full Python Info is: " + var_PY_ver_B + "\n")
        if arg_verbose_output == 1:
            print("[SYS]: O/S Version is: " + var_OS_main_ver)
            print("[SYS]: Python Version is: " + var_PY_ver_A)
            print("[SYS]: Full Python Info is: " + var_PY_ver_B)

########################################################################################################################################
################################################################# APK SEARCH ###########################################################
########################################################################################################################################
    
    if var_output_directory == '':
        var_output_directory = inputdirectory
        print("[INFO]: Output Directory is: " + var_output_directory)
    else:
        print("[INFO]: Output Directory is: " + var_output_directory)
    
    directory_search_pattern_check = (inputdirectory + "\\apk_storage\\")
    if os.path.isdir(directory_search_pattern_check):
        directory_search_pattern = (inputdirectory + "\\apk_storage\\*.apk")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Searching for APKs in: " + directory_search_pattern + "\n")
        if arg_verbose_output == 1:
            print("[INFO]: Searching for APKs in: " + directory_search_pattern)
            print("")

    else:
        directory_search_pattern = (inputdirectory+"\\*.apk")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Searching for APKs in: " + directory_search_pattern + "\n")
        if arg_verbose_output == 1:
            print("[INFO]: Searching for APKs in: " + directory_search_pattern)

    for apk_full_path in glob.glob(directory_search_pattern):
        if arg_verbose_output == 1:
            print("")
            print("############################################ RIPPING OF APK: " + os.path.basename(apk_full_path) + " STARTED. ##############################")
            print("")
        apk_with_extension = os.path.basename(apk_full_path)
        apk, discard_ext = os.path.splitext(apk_with_extension)
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Found The APK: " + apk_with_extension + " - Processing Now\n")
        if arg_verbose_output == 1:
            print("[INFO]: Found The APK: " + apk_with_extension + " - Processing Now")

########################################################################################################################################
####################################################### EXTRACTION DIRECTORY CREATION ##################################################
########################################################################################################################################
        global apk_main_pre_dir
        apk_main_pre_dir = var_output_directory + "\\apk_post_run\\"
        try:
            os.mkdir(apk_main_pre_dir)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making APK Results Directory: " + apk_main_pre_dir + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making APK Results Directory: " + apk_main_pre_dir + ". Directory likely exists.")

        global apk_main_dir
        apk_main_dir = apk_main_pre_dir + "\\" + timestr_dir
        try:
            os.mkdir(apk_main_dir)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making APK Results Directory: " + apk_main_dir + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making APK Results Directory: " + apk_main_dir + ". Directory likely exists.")

        global apk_main_dir_apk
        apk_main_dir_apk = apk_main_dir + "\\" + apk
        try:
            os.mkdir(apk_main_dir_apk)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making APK Results Directory: " + apk_main_dir_apk + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making APK Results Directory: " + apk_main_dir_apk + ". Directory likely exists.")
        
        global apk_source_directory
        apk_source_directory = apk_main_dir_apk + "\\" + "_0_source"
        try:
            os.mkdir(apk_source_directory)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making APK Results Directory: " + apk_source_directory + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making APK Results Directory: " + apk_source_directory + ". Directory likely exists.")
        
        global apk_decomp_directory
        apk_decomp_directory = apk_main_dir_apk + "\\" + "_1_decomp"
        try:
            os.mkdir(apk_decomp_directory)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making APK Results Directory: " + apk_decomp_directory + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making APK Results Directory: " + apk_decomp_directory + ". Directory likely exists.")

        global apk_results_directory
        apk_results_directory = apk_main_dir_apk + "\\" + "_2_results"
        try:
            os.mkdir(apk_results_directory)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making APK Results Directory: " + apk_results_directory + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making APK Results Directory: " + apk_results_directory + ". Directory likely exists.")
                
        global apk_extract_directory
        apk_extract_directory = apk_main_dir_apk + "\\" + "_3_extract"
        try:
            os.mkdir(apk_extract_directory)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making APK Results Directory: " + apk_extract_directory + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making APK Results Directory: " + apk_extract_directory + ". Directory likely exists.")
        
        if arg_autopsy_plugin == 1:
            var_information_true_filename = apk_with_extension[9:]
        else:
            var_information_true_filename = apk_with_extension

########################################################################################################################################
################################################## EXTRACTION FILE DEFINITION AND CREATION #############################################
########################################################################################################################################

        global cert_unproc_write_txt        
        global mani_unproc_write_txt
        global hashes_file_dump_txt
        global med_conf_URL_extract_write_txt
        global mod_conf_URL_extract_write_txt
        global low_conf_URL_extract_write_txt
        global hi_conf_URL_extract_write_txt
        global file_hashes_post_zip_extract
        global base64_extract_write_txt
        global ipv6_extract_write_txt
        global hi_conf_URL_extract_write_txt
        global ip_extract_write_txt
        global email_extract_write_txt
        global custom_search_write
        global count_stats_write_txt
        
        ipv6_extract_write_txt = apk_results_directory + "\\" + apk + "_regex_IPv6.txt"
        mani_unproc_write_txt = apk_results_directory + "\\" + apk + "_manifest_info_unproc.txt"
        hashes_file_dump_txt = apk_results_directory + "\\" + apk + "_hash_info.txt"
        cert_unproc_write_txt = apk_results_directory + "\\" + apk + "_cert_unproc.txt"
        ip_extract_write_txt = apk_results_directory + "\\" + apk + "_regex_IPv4.txt"
        med_conf_URL_extract_write_txt = apk_results_directory + "\\" + apk + "_med_conf_URL.txt"
        mod_conf_URL_extract_write_txt = apk_results_directory + "\\" + apk + "_mod_conf_URL.txt"
        low_conf_URL_extract_write_txt = apk_results_directory + "\\" + apk + "_low_conf_URL.txt"
        hi_conf_URL_extract_write_txt = apk_results_directory + "\\" + apk + "_hi_conf_URL.txt"
        file_hashes_post_zip_extract = apk_results_directory + "\\" + apk + "_hash_extract.txt"
        base64_extract_write_txt = apk_results_directory + "\\" + apk + "_base64_extract.txt"
        hi_conf_URL_extract_write_txt = apk_results_directory + "\\" + apk + "_med_conf_URL.txt"
        email_extract_write_txt = apk_results_directory + "\\" + apk + "_email_addr.txt"
        custom_search_write = apk_results_directory + "\\" + apk + "_search_hits.txt"
        count_stats_write_txt = apk_results_directory + "\\" + apk + "_stats.txt"
        
        global base64_extract_write_txt_up
        global mani_unproc_write_txt_update  
        global cert_unproc_txt_update
        global ip_extract_write_txt_update
        global med_conf_URL_extract_write_txt_up
        global low_conf_URL_extract_write_txt_up
        global file_txt_update
        global file_hashes_post_zip_extract_update
        global ipv6_extract_write_txt_up
        global hi_conf_URL_extract_write_txt_up
        global email_extract_write_txt_up
        global custom_search_write_up
        global count_stats_write_txt_up
        
        ip_extract_write_txt_update = open(ip_extract_write_txt, "a")
        cert_unproc_txt_update = open(cert_unproc_write_txt, "a")
        med_conf_URL_extract_write_txt_up = open(med_conf_URL_extract_write_txt, "a")
        mani_unproc_write_txt_update = open(mani_unproc_write_txt, "a")
        file_txt_update = open(hashes_file_dump_txt, "a")
        file_hashes_post_zip_extract_update = open(file_hashes_post_zip_extract, "a")
        base64_extract_write_txt_up = open(base64_extract_write_txt, "a")
        ipv6_extract_write_txt_up = open(ipv6_extract_write_txt, "a")
        hi_conf_URL_extract_write_txt_up = open(hi_conf_URL_extract_write_txt, "a")
        email_extract_write_txt_up = open(email_extract_write_txt, "a")
        custom_search_write_up = open(custom_search_write, "a")
        low_conf_URL_extract_write_txt_up = open(low_conf_URL_extract_write_txt, "a")
        count_stats_write_txt_up = open(count_stats_write_txt, "a")

        var_information_filename_write = ("[INFO]: True APK Filename is: " + var_information_true_filename + "\n")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: True APK Filename is: " + var_information_true_filename + "\n")
        if arg_verbose_output == 1:
            print("[INFO]: True APK Filename is: " + var_information_true_filename)


########################################################################################################################################
########################################################### APK HASHING FUNCTIONS ######################################################
########################################################################################################################################

        md5_hash = hashlib.md5()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                md5_hash.update(byte_block)
            apk_md5_hash = md5_hash.hexdigest()
            var_information_md5hash_write = ("[HASH]: MD5 Hash for: " + apk + ".apk is: " + apk_md5_hash + "\n")
            file_txt_update.write(var_information_md5hash_write)

        sha1_hash = hashlib.sha1()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha1_hash.update(byte_block)
            apk_sha1_hash = sha1_hash.hexdigest()
            var_information_sha1hash_write = ("[HASH]: SHA1 Hash for: " + apk + ".apk is: " + apk_sha1_hash + "\n")
            file_txt_update.write(var_information_sha1hash_write)

        sha256_hash = hashlib.sha256()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            apk_sha256_hash = sha256_hash.hexdigest()
            var_information_sha256hash_write = ("[HASH]: SHA256 Hash for: " + apk + ".apk is: " + apk_sha256_hash + "\n")
            file_txt_update.write(var_information_sha256hash_write)

        sha512_hash = hashlib.sha512()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha512_hash.update(byte_block)
            apk_sha512_hash = sha512_hash.hexdigest()
            var_information_sha512hash_write = ("[HASH]: SHA512 Hash for: " + apk + ".apk is: " + apk_sha512_hash + "\n")
            file_txt_update.write(var_information_sha512hash_write)

########################################################################################################################################
############################################################### JADX FUNCTIONS #########################################################
########################################################################################################################################

        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Starting JADX Decompiling of: " + apk_full_path + ".\n")   
        if arg_verbose_output == 1:
            print("")
            print("[JADX] ##################################### JADX DECOMPILING STARTED #############################################")
            print("")
            print("[JADX]: Started JADX Decompiling of: " + apk_full_path + ".")                                                                
        try:
            var_jadx_decomp = "\"" + apk_decomp_directory + "\\" + apk + "_source" + "\"" + " "
            jadx_apk_full_path = "\"" + apk_full_path + "\""
            var_jadx_command = '.\\win\\bin\\jadx.bat -d ' + var_jadx_decomp + " " + jadx_apk_full_path
            var_jadx_command_split = var_jadx_command.split()
            subprocess.check_call(var_jadx_command)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Decompiling: " + apk_full_path + " with JADX.\n")  
            if arg_verbose_output == 1:
                print("[WARN]: Error Decompiling: " + apk_full_path + " with JADX.")  

########################################################################################################################################
############################################################### YARA FUNCTIONS #########################################################
########################################################################################################################################

        if var_yara_flag == 1:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[INFO]: Starting YARA search of: " + apk_full_path + ".\n")   
            if arg_verbose_output == 1:
                print("")
                print("[YARA] ######################################## YARA SEARCH STARTED ###############################################")
                print("")
                print("[YARA]: Started YARA search within: " + apk_full_path + ".")                                                                
            try:
                var_yara_decomp = "\"" + apk_decomp_directory + "\\" + apk + "yara" + "\"" + " "
                
                yara_apk_full_path = "\"" + apk_full_path + "\""
                var_yara_command = '.\\win\\bin\\yara64.exe -s ' + " --recursive " + jadx_apk_full_path
                var_yara_command_split = var_yara_command.split()
                subprocess.check_call(var_yara_command)
            except:
                if var_forensic_case_bool == 1:
                    log_txt_update.write("[WARN]: Error Running YARA Against: " + apk_full_path + ".\n")  
                if arg_verbose_output == 1:
                    print("[WARN]: Error Running YARA Against: " + apk_full_path + ".")

########################################################################################################################################
####################################################### POST-Extraction File Locations #################################################
########################################################################################################################################

        global var_cert_RSA_location_dir
        global var_android_buildinfo_location
        var_cert_RSA_location_dir = apk_extract_directory + "\\META-INF\\"
        var_android_buildinfo_location = apk_extract_directory + "\\SEC-INF\\buildinfo.xml"

########################################################################################################################################
############################################################ UNZIP APK Extraction ######################################################
########################################################################################################################################
        
        global var_zip_success
        var_zip_success = 0
        
        try:
            with ZipFile(apk_full_path,"r") as var_apk_unzip:
                var_apk_unzip.extractall(apk_extract_directory + "\\")
                var_zip_success = 1
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Extracting: " + apk_full_path + "\n") 
            if arg_verbose_output == 1:
                print("[WARN]: Error Extracting: " + apk_full_path) 

        if var_zip_success == 1:
            func_hash_all_files()

########################################################################################################################################
####################################################### Certificate Analysis Function ##################################################
########################################################################################################################################            


        if var_forensic_case_bool == 1:
            log_txt_update.write("[CERT]: Started Certificate Processing of: " + apk_full_path + ".\n")   
        if arg_verbose_output == 1:
            print("")
            print("[CERT] ##################################### CERTIFICATE PROCESSING STARTED #############################################")
            print("")
            print("[CERT]: Started Certificate Processing of: " + apk_full_path + ".")         

        global var_bool_rsa_exists
        var_bool_rsa_exists = 0
        
        if os.path.exists(var_cert_RSA_location_dir):
            for var_files_rsa in os.listdir(var_cert_RSA_location_dir):
                if var_files_rsa.endswith(".RSA"):
                    var_bool_rsa_exists = var_bool_rsa_exists + 1
                    global var_cert_RSA_location
                    var_cert_RSA_location = var_cert_RSA_location_dir + "\\" + var_files_rsa
                    func_android_cert_pull()
                    
        if var_bool_rsa_exists == 0:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[CERT]: No Certificate Found For: " + apk_full_path + "\n") 
            if arg_verbose_output == 1:
                print("[CERT]: No Certificate Found For: " + apk_full_path)
                
        if var_bool_rsa_exists >= 2:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[CERT]: More Than One Certificate Found In: " + apk_full_path + "\n") 
            if arg_verbose_output == 1:
                print("[CERT]: More Than One Certificate Found In: " + apk_full_path)

########################################################################################################################################
######################################################## Manifest Analysis Function ####################################################
########################################################################################################################################    

        func_permission_checks()
        
########################################################################################################################################
##################################################### Extracted File Analysis Function #################################################
########################################################################################################################################    
    
        if var_python_version2_check == "TRUE":
            func_large_scale_regex()
        else:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Skipping REGEX Functionality, Python Version: " + var_python_version_info + " is unsupported." + "\n") 
            if arg_verbose_output == 1:
                print("[WARN]: Skipping REGEX Functionality, Python Version: " + var_python_version_info + " is unsupported.")


########################################################################################################################################
######################################################## POST-Extraction Statistics  ###################################################
########################################################################################################################################

        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Post-Extraction Statistics For: " + apk + "\n")  
        if arg_verbose_output == 1:      
            print("")
            print("[STATS] #################################### APK STATISTICS ####################################")
            print("")
            print("[INFO]: Post-Extraction Statistics Collection Started: " + apk)  
        function_statistic_write()

########################################################################################################################################
############################################################# Per APK Clean-Up #########################################################
########################################################################################################################################     

        if arg_verbose_output == 1:
            print("")
            print("[FIN] ###################################### FIN ######################################")
            print("")

        apk_move_cleanup_loc = apk_source_directory + "\\" + apk_with_extension
        try:
            shutil.move(apk_full_path, apk_move_cleanup_loc)
        except:
            log_txt_update.write("[WARN]: Error Moving APK: " + apk_full_path + " to: " + apk_move_cleanup_loc + "\n")
        file_txt_update.close()
    func_clean_up()

if __name__ == "__main__":
   main(sys.argv[1:])

###########################################################################
################################# ENDING ##################################
###########################################################################

############################### LEGAL NOTES ###############################

###########################################################################
###               Copyright (C)  2021  s3raph                             #
###                                                                       #
### This program is free software: you can redistribute it and/or modify  # 
### it under the terms of the GNU General Public License as published by  #
### the Free Software Foundation, either version 3 of the License, or     #
### (at your option) any later version.                                   #
###                                                                       #
### This program is distributed in the hope that it will be useful,       #
### but WITHOUT ANY WARRANTY; without even the implied warranty of        #
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         #
### GNU General Public License for more details.                          #
###                                                                       #
### You should have received a copy of the GNU General Public License     #  
### along with this program.                                              #
### If not, see <https://www.gnu.org/licenses/>.                          #
###########################################################################

################################## FIN ####################################
