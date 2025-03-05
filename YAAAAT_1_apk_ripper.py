########################################################################################################################################
#################################################### Author:      s3raph                ################################################
#################################################### Purpose:     To Pass the Butter    ################################################
#################################################### Version:     .07175                ################################################
#################################################### Last Update: 20230228              ################################################
########################################################################################################################################

import sys
import platform
import os
import fnmatch
import pandas
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
from subprocess import Popen
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
        var_python_version3_check = "false"
        var_python_version_info = "2.7+"
        var_py_complete_flag = 1
    elif sys.version_info >= (3, 0, 0):
        var_python_version2_check = "false"
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
    global dict_contained_libraries
    global dict_arch_support
    global dict_arm64_libaries
    global dict_arm64_lib_md5
    global dict_arm64_lib_sha256
    global dict_arm32_libaries
    global dict_arm32_lib_md5
    global dict_arm32_lib_sha256
    global dict_x64_libaries
    global dict_x64_lib_md5
    global dict_x64_lib_sha256
    global dict_contained_assets
    global dict_contained_assets_md5
    global dict_contained_assets_sha256
    global dict_directory_listing
    global dict_directory_file_listing
    global dict_ssdeep_so_output
    global var_ip_list_unscrubbed
    global var_proto_list_unscrubbed

    dict_contained_libraries = {}
    dict_arch_support = {}
    dict_arm64_libaries = {}
    dict_arm64_lib_md5 = {}
    dict_arm64_lib_sha256 = {}
    dict_arm32_libaries = {}
    dict_arm32_lib_md5 = {}
    dict_arm32_lib_sha256 = {}
    dict_x64_libaries = {}
    dict_x64_lib_md5 = {}
    dict_x64_lib_sha256 = {}
    dict_contained_assets = {}
    dict_contained_assets_md5 = {}
    dict_contained_assets_sha256 = {}
    dict_directory_listing = {}
    dict_directory_file_listing = {}
    dict_ssdeep_so_output = {}
    var_ip_list_unscrubbed = []
    var_proto_list_unscrubbed = []

    ### Known File Locations For Rip ###

    global cert_content_extract_sub
    global cert_content_extract_serial
    global cert_content_extract_algorithm
    global cert_content_extract_notbefore
    global cert_content_extract_notafter

    cert_content_extract_sub = ''
    cert_content_extract_serial = ''
    cert_content_extract_algorithm = ''
    cert_content_extract_notbefore = ''
    cert_content_extract_notafter = ''

def func_apk_json_map():
########################################################################################################################################
######################################################## JSON-PYTHON DICTIONARY MAP ####################################################
########################################################################################################################################
    apk_json = {
        "FILE-Filename": apk_with_extension,
        "FILE-True Filename": var_information_true_filename,
        #"FILE-Package Name": "", todo
        "FILE-Reported Location": apk_full_path,
        "FILE-Reported Device": "",
        "FILE-Contained Libraries": (dict_contained_libraries), #Tuple
        "FILE-Supported Architectures": (dict_arch_support), #Tuple
        "FILE-Contained Libraries ARM64": (dict_arm64_libaries), #Tuple
        "HASH-MD5 of Contained Libraries ARM64": (dict_arm64_lib_md5), #Tuple
        "HASH-SHA256 of Contained Libraries ARM64": (dict_arm64_lib_sha256), #Tuple
        "FILE-Contained Libraries ARM32": (dict_arm32_libaries), #Tuple
        "HASH-MD5 of Contained Libraries ARM32": (dict_arm32_lib_md5), #Tuple
        "HASH-SHA256 of Contained Libraries ARM32": (dict_arm32_lib_sha256), #Tuple
        "FILE-Contained Libraries x86": (dict_x86_libaries), #Tuple
        "HASH-MD5 of Contained Libraries x86": (dict_x86_lib_md5), #Tuple
        "HASH-SHA256 of Contained Libraries x86": (dict_x86_lib_sha256), #Tuple
        "FILE-Contained Libraries x64": (dict_x64_libaries), #Tuple
        "HASH-MD5 of Contained Libraries x64": (dict_x64_lib_md5), #Tuple
        "HASH-SHA256 of Contained Libraries x64": (dict_x64_lib_sha256), #Tuple
        "FILE-Contained Assets": (dict_contained_assets), #Tuple
        "HASH-MD5 of Contained Assets": (dict_contained_assets_md5), #Tuple
        "HASH-SHA256 of Contained Assets": (dict_contained_assets_sha256), #Tuple
        "FILE-Directory Listing": (dict_directory_listing), #Tuple
        "FILE-Directory And File Listing": (dict_directory_file_listing), #Tuple
        "SO-SSDEEP Parsed Data": (dict_ssdeep_so_output), #Tuple
        "HASH-MD5 Hash": apk_md5_hash,
        "HASH-SHA1 Hash": apk_sha1_hash,
        "HASH-SHA256 Hash": apk_sha256_hash,
        "HASH-SHA512 Hash": apk_sha512_hash,
        "CERT-APK Signature Subject": cert_content_extract_subject,
        "CERT-APK Signature Serial": cert_content_extract_serial,
        "PERM-ACCEPT_HANDOVER": var_perm_accept_handover,
        "PERM-ACCESS_BACKGROUND_LOCATION": var_perm_access_background_location,
        "PERM-ACCESS_BLOBS_ACROSS_USERS": var_perm_access_blobs_across_users,
        "PERM-ACCESS_CHECKIN_PROPERTIES": var_perm_access_checkin_properties,
        "PERM-ACCESS_COARSE_LOCATION": var_perm_access_coarse_location,
        "PERM-ACCESS_FINE_LOCATION": var_perm_access_fine_location,
        "PERM-ACCESS_LOCATION_EXTRA_COMMANDS": var_perm_access_location_extra_commands,
        "PERM-ACCESS_MEDIA_LOCATION": var_perm_access_media_location,
        "PERM-ACCESS_NETWORK_STATE": var_perm_access_network_state,
        "PERM-ACCESS_NOTIFICATION_POLICY": var_perm_access_notification_policy,
        "PERM-ACCESS_WIFI_STATE": var_perm_access_wifi_state,
        "PERM-ADD_VOICEMAIL": var_perm_add_voicemail,
        "PERM-ACCOUNT_MANAGER": var_perm_account_manager,
        "PERM-ACTIVITY_RECOGNITION": var_perm_activity_recognition,
        "PERM-ANSWER_PHONE_CALLS": var_perm_answer_phone_calls,
        "PERM-BATTERY_STATS": var_perm_battery_stats,
        "PERM-BIND_ACCESSIBILITY_SERVICE": var_perm_bind_accessibility_service,
        "PERM-BIND_APPWIDGET": var_perm_bind_appwidget,
        "PERM-BIND_AUTOFILL_SERVICE": var_perm_bind_autofill_service,
        "PERM-BIND_CALL_REDIRECTION_SERVICE": var_perm_bind_call_redirection_service,
        "PERM-BIND_CARRIER_MESSAGING_CLIENT_SERVICE": var_perm_bind_carrier_messaging_client_service,
        "PERM-BIND_CARRIER_MESSAGING_SERVICE": var_perm_bind_carrier_messaging_service,
        "PERM-BIND_CARRIER_SERVICES": var_perm_bind_carrier_services,
        "PERM-BIND_CHOOSER_TARGET_SERVICE": var_perm_bind_chooser_target_service,
        "PERM-BIND_COMPANION_DEVICE_SERVICE": var_perm_bind_companion_device_service,
        "PERM-BIND_CONDITION_PROVIDER_SERVICE": var_perm_bind_condition_provider_service,
        "PERM-BIND_CONTROLS": var_perm_bind_controls,
        "PERM-BIND_DEVICE_ADMIN": var_perm_bind_device_admin,
        "PERM-BIND_DREAM_SERVICE": var_perm_bind_dream_service,
        "PERM-BIND_INCALL_SERVICE": var_perm_bind_incall_service,
        "PERM-BIND_INPUT_METHOD": var_perm_bind_input_method,
        "PERM-BIND_MIDI_DEVICE_SERVICE": var_perm_bind_midi_device_service,
        "PERM-BIND_NFC_SERVICE": var_perm_bind_nfc_service,
        "PERM-BIND_NOTIFICATION_LISTENER_SERVICE": var_perm_bind_notification_listener_service,
        "PERM-BIND_PRINT_SERVICE": var_perm_bind_print_service,
        "PERM-BIND_QUICK_ACCESS_WALLET_SERVICE": var_perm_bind_quick_access_wallet_service,
        "PERM-BIND_QUICK_SETTINGS_TILE": var_perm_bind_quick_settings_tile,
        "PERM-BIND_REMOTEVIEWS": var_perm_bind_remoteviews,
        "PERM-BIND_SCREENING_SERVICE": var_perm_bind_screening_service,
        "PERM-BIND_TELECOM_CONNECTION_SERVICE": var_perm_bind_telecom_connection_service,
        "PERM-BIND_TEXT_SERVICE": var_perm_bind_text_service,
        "PERM-BIND_TV_INPUT": var_perm_bind_tv_input,
        "PERM-BIND_VISUAL_VOICEMAIL_SERVICE": var_perm_bind_visual_voicemail_service,
        "PERM-BIND_VOICE_INTERACTION": var_perm_bind_voice_interaction,
        "PERM-BIND_VPN_SERVICE": var_perm_bind_vpn_service,
        "PERM-BIND_VR_LISTENER_SERVICE": var_perm_bind_vr_listener_service,
        "PERM-BIND_WALLPAPER": var_perm_bind_wallpaper,
        "PERM-BLUETOOTH": var_perm_bluetooth,
        "PERM-BLUETOOTH_ADMIN": var_perm_bluetooth_admin,
        "PERM-BLUETOOTH_ADVERTISE": var_perm_bluetooth_advertise,
        "PERM-BLUETOOTH_CONNECT": var_perm_bluetooth_connect,
        "PERM-BLUETOOTH_PRIVILEGED": var_perm_bluetooth_privileged,
        "PERM-BLUETOOTH_SCAN": var_perm_bluetooth_scan,
        "PERM-BODY_SENSORS": var_perm_body_sensors,
        "PERM-BROADCAST_PACKAGE_REMOVED": var_perm_broadcast_package_removed,
        "PERM-BROADCAST_SMS": var_perm_broadcast_sms,
        "PERM-BROADCAST_STICKY": var_perm_broadcast_sticky,
        "PERM-BROADCAST_WAP_PUSH": var_perm_broadcast_wap_push,
        "PERM-CALL_COMPANION_APP": var_perm_call_companion_app,
        "PERM-CALL_PHONE": var_perm_call_phone,
        "PERM-CALL_PRIVILEGED": var_perm_call_privileged,
        "PERM-CAMERA": var_perm_camera,
        "PERM-CAPTURE_AUDIO_OUTPUT": var_perm_capture_audio_output,
        "PERM-CHANGE_COMPONENT_ENABLED_STATE": var_perm_change_component_enabled_state,
        "PERM-CHANGE_CONFIGURATION": var_perm_change_configuration,
        "PERM-CHANGE_NETWORK_STATE": var_perm_change_network_state,
        "PERM-CHANGE_WIFI_MULTICAST_STATE": var_perm_change_wifi_multicast_state,
        "PERM-CHANGE_WIFI_STATE": var_perm_change_wifi_state,
        "PERM-CLEAR_APP_CACHE": var_perm_clear_app_cache,
        "PERM-CONTROL_LOCATION_UPDATES": var_perm_control_location_updates,
        "PERM-DELETE_CACHE_FILES": var_perm_delete_cache_files,
        "PERM-DELETE_PACKAGES": var_perm_delete_packages,
        "PERM-DIAGNOSTIC": var_perm_diagnostic,
        "PERM-DISABLE_KEYGUARD": var_perm_disable_keyguard, # Probs bad
        "PERM-DUMP": var_perm_dump,
        "PERM-EXPAND_STATUS_BAR": var_perm_expand_status_bar,
        "PERM-FACTORY_TEST": var_perm_factory_test,
        "PERM-FOREGROUND_SERVICE": var_perm_foreground_service,
        "PERM-GET_ACCOUNTS": var_perm_get_accounts,
        "PERM-GET_ACCOUNTS_PRIVILEGED": var_perm_get_accounts_privileged,
        "PERM-GET_PACKAGE_SIZE": var_perm_get_package_size,
        "PERM-GET_TASKS": var_perm_get_tasks,
        "PERM-GLOBAL_SEARCH": var_perm_global_search,
        "PERM-HIDE_OVERLAY_WINDOWS": var_perm_hide_overlay_windows,
        "PERM-HIGH_SAMPLING_RATE_SENSORS": var_perm_high_sampling_rate_sensors,
        "PERM-INSTALL_LOCATION_PROVIDER": var_perm_install_location_provider,
        "PERM-INSTALL_PACKAGES": var_perm_install_packages,
        "PERM-INSTALL_SHORTCUT": var_perm_install_shortcut,
        "PERM-INSTANT_APP_FOREGROUND_SERVICE": var_perm_instant_app_foreground_service,
        "PERM-INTERACT_ACROSS_PROFILES": var_perm_interact_across_profiles,
        "PERM-INTERNET": var_perm_internet,
        "PERM-KILL_BACKGROUND_PROCESSES": var_perm_kill_background_processes,
        "PERM-LAUNCH_TWO_PANE_SETTINGS_DEEP_LINK": var_perm_launch_two_pane_settings_deep_link,
        "PERM-LOADER_USAGE_STATS": var_perm_loader_usage_stats,
        "PERM-LOCATION_HARDWARE": var_perm_location_hardware,
        "PERM-MANAGE_DOCUMENTS": var_perm_manage_documents,
        "PERM-MANAGE_EXTERNAL_STORAGE": var_perm_manage_external_storage,
        "PERM-MANAGE_MEDIA": var_perm_manage_media,
        "PERM-MANAGE_ONGOING_CALLS": var_perm_manage_ongoing_calls,
        "PERM-MANAGE_OWN_CALLS": var_perm_manage_own_calls,
        "PERM-MASTER_CLEAR": var_perm_master_clear, # Unusual Call
        "PERM-MEDIA_CONTENT_CONTROL": var_perm_media_content_control,
        "PERM-MODIFY_AUDIO_SETTINGS": var_perm_modify_audio_settings,
        "PERM-MODIFY_PHONE_STATE": var_perm_modify_phone_state,
        "PERM-MOUNT_FORMAT_FILESYSTEMS": var_perm_mount_format_filesystems,
        "PERM-MOUNT_UNMOUNT_FILESYSTEMS": var_perm_mount_unmount_filesystems,
        "PERM-NFC": var_perm_nfc,
        "PERM-NFC_PREFERRED_PAYMENT_INFO": var_perm_nfc_preferred_payment_info,
        "PERM-NFC_TRANSACTION_EVENT": var_perm_nfc_transaction_event,
        "PERM-PACKAGE_USAGE_STATS": var_perm_package_usage_stats,
        "PERM-PERSISTENT_ACTIVITY": var_perm_persistent_activity,
        "PERM-PROCESS_OUTGOING_CALLS": var_perm_process_outgoing_calls,
        "PERM-QUERY_ALL_PACKAGES": var_perm_query_all_packages,
        "PERM-READ_CALENDAR": var_perm_read_calendar,
        "PERM-READ_CALL_LOG": var_perm_read_call_log,
        "PERM-READ_CONTACTS": var_perm_read_contacts,
        "PERM-READ_EXTERNAL_STORAGE": var_perm_read_external_storage,
        "PERM-READ_INPUT_STATE": var_perm_read_input_state,
        "PERM-READ_LOGS": var_perm_read_logs,
        "PERM-READ_PHONE_NUMBERS": var_perm_read_phone_numbers,
        "PERM-READ_PHONE_STATE": var_perm_read_phone_state,
        "PERM-READ_PRECISE_PHONE_STATE": var_perm_read_precise_phone_state,
        "PERM-READ_SMS": var_perm_read_sms,
        "PERM-READ_SYNC_SETTINGS": var_perm_read_sync_settings,
        "PERM-READ_SYNC_STATS": var_perm_read_sync_stats,
        "PERM-READ_VOICEMAIL": var_perm_read_voicemail,
        "PERM-REBOOT": var_perm_reboot,
        "PERM-RECEIVE_BOOT_COMPLETED": var_perm_receive_boot_completed,
        "PERM-RECEIVE_MMS": var_perm_receive_mms,
        "PERM-RECEIVE_SMS": var_perm_receive_sms,
        "PERM-RECEIVE_WAP_PUSH": var_perm_receive_wap_push,
        "PERM-RECORD_AUDIO": var_perm_record_audio,
        "PERM-REORDER_TASKS": var_perm_reorder_tasks,
        "PERM-REQUEST_COMPANION_PROFILE_WATCH": var_perm_request_companion_profile_watch,
        "PERM-REQUEST_COMPANION_RUN_IN_BACKGROUND": var_perm_request_companion_run_in_background,
        "PERM-REQUEST_COMPANION_START_FOREGROUND_SERVICES_FROM_BACKGROUND": var_perm_request_companion_start_foreground_services_from_background,
        "PERM-REQUEST_COMPANION_USE_DATA_IN_BACKGROUND": var_perm_request_companion_use_data_in_background,
        "PERM-REQUEST_DELETE_PACKAGES": var_perm_request_delete_packages,
        "PERM-REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": var_perm_request_ignore_battery_optimizations,
        "PERM-REQUEST_INSTALL_PACKAGES": var_perm_request_install_packages,
        "PERM-REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE": var_perm_request_observe_companion_device_presence,
        "PERM-REQUEST_PASSWORD_COMPLEXITY": var_perm_request_password_complexity,
        "PERM-RESTART_PACKAGES": var_perm_restart_packages,
        "PERM-SCHEDULE_EXACT_ALARM": var_perm_schedule_exact_alarm,
        "PERM-SEND_RESPOND_VIA_MESSAGE": var_perm_send_respond_via_message,
        "PERM-SEND_SMS": var_perm_send_sms,
        "PERM-SET_ALARM": var_perm_set_alarm,
        "PERM-SET_ALWAYS_FINISH": var_perm_set_always_finish,
        "PERM-SET_ANIMATION_SCALE": var_perm_set_animation_scale,
        "PERM-SET_DEBUG_APP": var_perm_set_debug_app,
        "PERM-SET_PREFERRED_APPLICATIONS": var_perm_set_preferred_applications,
        "PERM-SET_PROCESS_LIMIT": var_perm_set_process_limit,
        "PERM-SET_TIME": var_perm_set_time,
        "PERM-SET_TIME_ZONE": var_perm_set_time_zone,
        "PERM-SET_WALLPAPER": var_perm_set_wallpaper,
        "PERM-SET_WALLPAPER_HINTS": var_perm_set_wallpaper_hints,
        "PERM-SIGNAL_PERSISTENT_PROCESSES": var_perm_signal_persistent_processes,
        "PERM-SMS_FINANCIAL_TRANSACTIONS": var_perm_sms_financial_transactions,
        "PERM-START_FOREGROUND_SERVICES_FROM_BACKGROUND": var_perm_start_foreground_services_from_background,
        "PERM-START_VIEW_PERMISSION_USAGE": var_perm_start_view_permission_usage,
        "PERM-STATUS_BAR": var_perm_status_bar,
        "PERM-SYSTEM_ALERT_WINDOW": var_perm_system_alert_window,
        "PERM-TRANSMIT_IR": var_perm_transmit_ir,
        "PERM-UNINSTALL_SHORTCUT": var_perm_uninstall_shortcut, # Odd call
        "PERM-UPDATE_DEVICE_STATS": var_perm_update_device_stats,
        "PERM-UPDATE_PACKAGES_WITHOUT_USER_ACTION": var_perm_update_packages_without_user_action,
        "PERM-USE_BIOMETRIC": var_perm_use_biometric,
        "PERM-USE_FINGERPRINT": var_perm_use_fingerprint,
        "PERM-USE_FULL_SCREEN_INTENT": var_perm_use_full_screen_intent,
        "PERM-USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER": var_perm_use_icc_auth_with_device_identifier,
        "PERM-USE_SIP": var_perm_use_sip,
        "PERM-UWB_RANGING": var_perm_uwb_ranging,
        "PERM-VIBRATE": var_perm_vibrate,
        "PERM-WAKE_LOCK": var_perm_wake_lock,
        "PERM-WRITE_APN_SETTINGS": var_perm_write_apn_settings,
        "PERM-WRITE_CALENDAR": var_perm_write_calendar,
        "PERM-WRITE_CALL_LOG": var_perm_write_call_log,
        "PERM-WRITE_CONTACTS": var_perm_write_contacts,
        "PERM-WRITE_EXTERNAL_STORAGE": var_perm_write_external_storage,
        "PERM-WRITE_GSERVICES": var_perm_write_gservices,
        "PERM-WRITE_SECURE_SETTINGS": var_perm_write_secure_settings,
        "PERM-WRITE_SETTINGS": var_perm_write_settings,
        "PERM-WRITE_SYNC_SETTINGS": var_perm_write_sync_settings,
        "PERM-WRITE_VOICEMAIL": var_perm_write_voicemail
    }

    #def pad_dict_list(dict_list, padel):
    #    lmax = 0
    #    for lname in dict_list.keys():
    #        lmax = max(lmax, len(dict_list[lname]))
    #    for lname in dict_list.keys():
    #        ll = len(dict_list[lname])
    #        if  ll < lmax:
    #            dict_list[lname] += [padel] * (lmax - ll)
    #    return dict_list

    #try:
    #    var_inputjson = json.dumps(apk_json)
    #    var_inputjson = pad_dict_list(var_inputjson, 0)
    #    var_jsonconvert = pandas.DataFrame.from_dict(var_inputjson, orient='index')
    #    var_jsonconvert = var_jsonconvert.transpose()
    #    var_jsonconvert.to_csv('csvfile.csv', encoding='utf-8', index=False)
    #except:
    #    if var_forensic_case_bool == 1:
    #        log_txt_update.write("[WARN]: Error Converting JSON to CSV: " + var_inputjson + "\n")
    #    if arg_verbose_output == 1:
    #        print("[WARN]: Error Converting JSON to CSV: " + var_inputjson + "\n")


def func_find_javahome():
########################################################################################################################################
############################################################ Find JDK Function #########################################################
########################################################################################################################################
    global var_jdk_keytool_location
    var_jdk_keytool_location = ''
    if 'JAVA_HOME' in os.environ:
        var_jdk_loc_1 = os.environ['JAVA_HOME']
        if "jdk" in var_jdk_loc_1:
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

def func_so_ssdeep_parser():
    global var_so_ssdeep_list
    var_so_ssdeep_list = []
    
    if os.path.exists(var_ssdeep_output_temp):
        with open(var_ssdeep_output_temp) as var_ssdeep_output_temp_extract_file:
            var_ssdeep_output_temp_extract = var_ssdeep_output_temp_extract_file.readlines()
            for line in var_ssdeep_output_temp_extract:
                line = line.replace("[", "")
                line = line.replace("]", "")
                var_ssdeep_extract_so_details = re.findall(r'[0-9a-zA-Z+/]*:', line)
                var_ssdeep_extract_so_details_blocksize = var_ssdeep_extract_so_details[0].replace(":", "")
                var_ssdeep_extract_so_details_hash1 = var_ssdeep_extract_so_details[1].replace(":", "")
                var_ssdeep_extract_so_details_2 = re.findall(r'[0-9a-zA-Z+/]*,', line)
                var_ssdeep_extract_so_details_hash2 = var_ssdeep_extract_so_details_2[0].replace(",", "")
        var_so_ssdeep_list = [var_ssdeep_file_name, var_ssdeep_extract_so_details_blocksize, var_ssdeep_extract_so_details_hash1, var_ssdeep_extract_so_details_hash2]
        dict_ssdeep_so_output.append(var_so_ssdeep_list)
        var_ssdeep_log_txt_up.write("[SO] Filename: " + var_ssdeep_file_name + "\n")
        var_ssdeep_log_txt_up.write("[SO] Blocksize: " + var_ssdeep_extract_so_details_blocksize + "\n")
        var_ssdeep_log_txt_up.write("[SO] Hash 1: " + var_ssdeep_extract_so_details_hash1 + "\n")
        var_ssdeep_log_txt_up.write("[SO] Hash 2: " + var_ssdeep_extract_so_details_hash2 + "\n")
        var_ssdeep_log_txt_up.write("\n")

def func_so_fileheader_check():
########################################################################################################################################
########################################################### SO FILE HEADER CHECK #######################################################
########################################################################################################################################
    global so_file_header_check
    global so_file_header_check_data
    global so_file_header_sig
    global so_extract_continue
    
    so_file_header_check = open(var_tmp_so_path, "rb")
    so_file_header_check_data = so_file_header_check.read(4)
    so_file_header_sig = "ELF"
    so_extract_continue = 0
        
    if so_file_header_sig in so_file_header_check_data:
        so_extract_continue = 1
        so_file_header_check.close()
        if var_forensic_case_bool == 1:
            log_txt_update.write("[HEADER]: File Header: " + so_full_path + " matches that of a SO.\n")
        if arg_verbose_output == 1:
            print("[HEADER]: File Header: " + so_full_path + " matches that of a SO.")

    else:
        apk_file_header_check.close()
        if var_forensic_case_bool == 1:
            log_txt_update.write("[HEADER] File Header: " + so_full_path + " does not match that of a SO. Skipping Processing.\n")
        if arg_verbose_output == 1:
            print("[HEADER] File Header: " + so_full_path + " does not match that of a SO. Skipping Processing.")

def func_so_ssdeep_poll():
########################################################################################################################################
############################################################ SO SSDEEP ANALYSIS ########################################################
########################################################################################################################################
    global var_ssdeep_output_temp
    global var_ssdeep_file_name
    var_ssdeep_output_temp = ""
    var_ssdeep_file_name = ""
    
    if var_tmp_so_path != "":
        try:
            os.system(".\\win\\ssdeep.exe -c -l " + var_tmp_so_path + " >> " + apk_results_directory + "\\" + apk + "_embedso_" + filename + "_ssdeep_output.txt")
            var_ssdeep_output_temp = (apk_results_directory + "\\" + apk + "_embedso_" + filename + "_ssdeep_output.txt")
            var_ssdeep_file_name = filename
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: ssdeep failed to run against: " + var_tmp_so_path + "\n")
            if arg_verbose_output == 1:
                print("[WARN]: ssdeep failed to run against: " + var_tmp_so_path)
        func_so_ssdeep_parser()
    if var_tmp_so_path == "":
        if var_forensic_case_bool == 1:
            log_txt_update.write("[WARN]: ssdeep cannot run, SO path is empty\n")
        if arg_verbose_output == 1:
            print("[WARN]: ssdeep cannot run, SO path is empty")

def func_so_finder_within_apk_ripper():
########################################################################################################################################
################################################################# SO FINDER ############################################################
########################################################################################################################################
    global directory_search_pattern
    global so_full_path
    global filename
    so_full_path = ""
    filename = ""
    directory_search_pattern = ""
    
    directory_search_pattern_check_2 = (apk_extract_directory)
    if os.path.isdir(directory_search_pattern_check_2):
        directory_search_pattern = (apk_extract_directory + "\\*.so")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Searching for SOs in: " + directory_search_pattern + "\n")
        if arg_verbose_output == 1:
            print("")
            print("[INFO]: Searching for SOs in: " + directory_search_pattern)
            print("")
    
    if directory_search_pattern != "":
        for root, dirnames, filenames in os.walk(apk_extract_directory):
            for filename in fnmatch.filter(filenames, '*.so'):
                so_full_path = (root + "\\" + filename)
                if so_full_path != "":
                    global var_tmp_so_path
                    var_tmp_so_path = ""
                    var_tmp_so_path = so_full_path
                    func_so_fileheader_check()
                    if so_extract_continue == 0:
                        continue
                    if arg_verbose_output == 1:
                        print("")
                        print("############################################ Found SO: " + os.path.basename(so_full_path) + " STARTED. ##############################")
                        print("")
                    so_with_extension = os.path.basename(so_full_path)
                    so, discard_ext = os.path.splitext(so_with_extension)
                    if var_forensic_case_bool == 1:
                        log_txt_update.write("[INFO]: Found The so: " + so_with_extension + " - Processing Now\n")
                    if arg_verbose_output == 1:
                        print("[INFO]: Found SO: " + so_with_extension + " - Processing Now")
                    func_so_ssdeep_poll()
    else:
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Directory Search Pattern: " + directory_search_pattern + " appears empty\n")
        if arg_verbose_output == 1:
            print("[INFO]: Directory Search Pattern: " + directory_search_pattern + " appears empty")

def func_fileheader_check():
########################################################################################################################################
############################################################ Fileheader Function #######################################################
########################################################################################################################################

    global apk_file_header_check
    global apk_file_header_check_data
    global apk_file_header_sig
    global apk_extract_continue
    
    apk_file_header_check = open(apk_full_path, "rb")
    apk_file_header_check_data = apk_file_header_check.read(2)
    apk_file_header_sig = "PK"

    apk_extract_continue = 0
        
    if apk_file_header_sig in apk_file_header_check_data:
        apk_extract_continue = 1
        apk_file_header_check.close()
        if var_forensic_case_bool == 1:
            log_txt_update.write("[HEADER]: File Header: " + apk_full_path + " matches that of an APK.\n")
        if arg_verbose_output == 1:
            print("[HEADER]: File Header: " + apk_full_path + " matches that of an APK.")

    else:
        apk_file_header_check.close()
        if var_forensic_case_bool == 1:
            log_txt_update.write("[HEADER] File Header: " + apk_full_path + " does not match that of an APK. Skipping Processing.\n")
        if arg_verbose_output == 1:
            print("[HEADER] File Header: " + apk_full_path + " does not match that of an APK. Skipping Processing.")

def func_android_cert_pull():
########################################################################################################################################
####################################################### APK Certificate Rip Function ###################################################
########################################################################################################################################
    global var_path_to_android_xml
    global var_cert_RSA_location
    global var_android_buildinfo_location
    global cert_content_extract_serial
    global cert_content_extract_sub
    global cert_content_extract_algorithm
    global cert_content_extract_notbefore
    global cert_content_extract_notafter
    
    func_find_javahome()

    var_x_int = 0

    if var_jdk_keytool_location != '':
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
                cert_content_extract_serial = var_each_extract_serial
            cert_content_extract_owner = re.findall('Owner:(.*)', temp_certificate_txt_file_line)
            for var_each_extract_owner in cert_content_extract_owner:
                cert_unproc_txt_update.write("[Method KT]: APK Certificate Owner: " + var_each_extract_owner + "\n")
                cert_content_extract_sub = var_each_extract_owner
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
                cert_content_extract_serial = var_each_cert_serial
            cert_content_extract_subject = re.findall('Subject:(.*)', temp_certificate_txt_file_line)
            for var_each_cert_subject in cert_content_extract_subject:
                cert_unproc_txt_update.write("[Method 1]: APK Certificate Subject: " + var_each_cert_subject + "\n")
                cert_content_extract_sub = var_each_cert_subject
            cert_content_extract_sigalg = re.findall('Signature Algorithm:(.*)', temp_certificate_txt_file_line)
            for var_each_cert_sigalg in cert_content_extract_sigalg:
                cert_unproc_txt_update.write("[Method 1]: APK Certificate Signature Algorithm: " + var_each_cert_sigalg + "\n")
                cert_content_extract_algorithm = var_each_cert_sigalg

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
            cert_content_extract_serial = cert_content_extract_serial
            cert_unproc_txt_update.write("[Method 2]: APK Certificate Subject: " + cert_content_extract_subject + "\n")
            cert_content_extract_sub = cert_content_extract_subject
            cert_unproc_txt_update.write("[Method 2]: APK Certificate Algorithm: " + cert_content_extract_algorithm + "\n")
            cert_content_extract_algorithm = cert_content_extract_algorithm
            cert_unproc_txt_update.write("[Method 2]: APK Certificate Not Before: " + cert_content_extract_notbefore + "\n")
            cert_content_extract_notbefore = cert_content_extract_notbefore
            cert_unproc_txt_update.write("[Method 2]: APK Certificate Not After: " + cert_content_extract_notafter + "\n")
            cert_content_extract_notafter = cert_content_extract_notafter

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
    global apk_content_extract_ipv6_len

    var_url_high_count = 0
    var_url_med_count = 0
    var_url_low_count = 0
    var_IPv4_count = 0
    var_IPv6_low_count = 0
    var_IPv6_high_count = 0
    var_search_hits = 0
    var_email_count = 0
    apk_content_extract_ipv6_len = 0
        
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
                        ip_extract_write_txt_update.write("[IPV4] SOURCE FILE: " + var_ref_filepath + "\n")
                        ip_extract_write_txt_update.write("[IPV4] SOURCE LINE: " + var_directory_file_object_line.strip('\n') + "\n")                    
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
                        apk_content_extract_ipv6 = re.findall(r'((?:^|(?<=\s))(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?=\s|$))', var_directory_file_object_line)
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


########################################################################################################################################
########################################################## PERMISSION JSON EXTRACT #####################################################
########################################################################################################################################
def func_manifest_check():
    for var_each_mani_permission_v3,var_manifest_dict_data in json_manifest_master_dict.items():
        if var_each_mani_permission_v2 == var_each_mani_permission_v3:
            var_each_mani_permission_v3 = var_each_mani_permission_v3.lower()
            globals()["var_perm_" + var_each_mani_permission_v3] = 1

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
    global var_each_mani_permission
    global var_each_mani_permission_v2
    
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
                for var_each_mani_permission_v2 in mani_content_extract_permission:
                    if var_each_mani_permission_v2 != None:
                        func_manifest_check()
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
                    var_json_append_tmp_md5 = {}
                    var_json_append_tmp_md5 = {var_each_file: file_md5_hash}
                    dict_contained_assets_md5.append(var_json_append_tmp_md5)
                    var_json_append_tmp_filedir = {}
                    var_ref_filepath_tmp_str = "\\" + var_ref_filepath.split(os.path.sep)[-4] + "\\" + var_ref_filepath.split(os.path.sep)[-3]  + "\\" + var_ref_filepath.split(os.path.sep)[-2] + "\\" + var_ref_filepath.split(os.path.sep)[-1]
                    var_json_append_tmp_filedir = {file_md5_hash: var_ref_filepath_tmp_str} ## find method for relational (i.e. ./apk/_0_source/...
                    dict_directory_file_listing.append(var_json_append_tmp_filedir)

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
                    var_json_append_tmp_sha256 = {}
                    var_json_append_tmp_sha256 = {var_each_file: file_sha256_hash}
                    dict_contained_assets_sha256.append(var_json_append_tmp_sha256)

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
    global apk_full_path
    global apk_with_extension
    global var_information_true_filename
    
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

    inputdirectory = inputdirectory_var
    if var_output_directory == '':
        var_output_directory = inputdirectory
        if arg_verbose_output == 1:
            print("[INFO]: Output Directory is: " + var_output_directory)
    if arg_verbose_output == 1:
        print("[INFO]: Input Directory is: " + inputdirectory)

    outputdirectory = os.path.dirname(var_output_directory)
    if var_forensic_case_bool == 1:
        var_case_delivery_directory = outputdirectory + "\\" + timestr_case + "_case_info"
        if os.path.exists(var_case_delivery_directory):
            print("[INFO]: Case Directory: " + var_case_delivery_directory + " Already Exists")
        else:
            try:
                os.mkdir(var_case_delivery_directory)
            except:
                print("[WARN]: Error Making Main Case Directory: " + var_case_delivery_directory)
        func_initial_logging()
        func_determine_operating_system()

    if var_forensic_case_bool == 1:
        log_txt_update.write("[INFO]: Input Directory is: " + inputdirectory + "\n")
    if arg_verbose_output == 1:
        print("[INFO]: Output Directory is: " + var_output_directory)

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
        func_fileheader_check()
        if apk_extract_continue == 0:
            continue
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
        global var_yara_log_txt
        global var_ssdeep_log_txt
        
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
        var_yara_log_txt = apk_results_directory + "\\" + apk + "_yara_hits.txt"
        var_ssdeep_log_txt = apk_results_directory + "\\" + apk + "_ssdeep_log.txt"
        
        
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
        global var_yara_log_write_txt_up
        global var_ssdeep_log_txt_up
        
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
        var_yara_log_write_txt_up = open(var_yara_log_txt, "a")
        var_ssdeep_log_txt_up = open(var_ssdeep_log_txt, "a")

        var_information_filename_write = ("[INFO]: True APK Filename is: " + var_information_true_filename + "\n")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: True APK Filename is: " + var_information_true_filename + "\n")
        if arg_verbose_output == 1:
            print("[INFO]: True APK Filename is: " + var_information_true_filename)

########################################################################################################################################
###################################################### Permission Variable Definitions #################################################
########################################################################################################################################
################################################ Yes this is a bit unwieldy but I don't care ###########################################
########################################################################################################################################

        global json_manifest_master_dict
        
        json_manifest_master_dict = { 'ACCESS_ALL_DOWNLOADS': 0,'ACCESS_BLUETOOTH_SHARE': 0,'ACCESS_CACHE_FILESYSTEM': 0,'ACCESS_CHECKIN_PROPERTIES': 0,'ACCESS_CONTENT_PROVIDERS_EXTERNALLY': 0,'ACCESS_DOWNLOAD_MANAGER': 0,'ACCESS_DOWNLOAD_MANAGER_ADVANCED': 0,'ACCESS_DRM_CERTIFICATES': 0,'ACCESS_EPHEMERAL_APPS': 0,'ACCESS_FM_RADIO': 0,'ACCESS_INPUT_FLINGER': 0,'ACCESS_KEYGUARD_SECURE_STORAGE': 0,'ACCESS_LOCATION_EXTRA_COMMANDS': 0,'ACCESS_MOCK_LOCATION': 0,'ACCESS_MTP': 0,'ACCESS_NETWORK_CONDITIONS': 0,'ACCESS_NETWORK_STATE': 0,'ACCESS_NOTIFICATIONS': 0,'ACCESS_NOTIFICATION_POLICY': 0,'ACCESS_PDB_STATE': 0,'ACCESS_SURFACE_FLINGER': 0,'ACCESS_VOICE_INTERACTION_SERVICE': 0,'ACCESS_VR_MANAGER': 0,'ACCESS_WIFI_STATE': 0,'ACCESS_WIMAX_STATE': 0,'ACCOUNT_MANAGER': 0,'ALLOW_ANY_CODEC_FOR_PLAYBACK': 0,'ASEC_ACCESS': 0,'ASEC_CREATE': 0,'ASEC_DESTROY': 0,'ASEC_MOUNT_UNMOUNT': 0,'ASEC_RENAME': 0,'AUTHENTICATE_ACCOUNTS': 0,'BACKUP': 0,'BATTERY_STATS': 0,'BIND_ACCESSIBILITY_SERVICE': 0,'BIND_APPWIDGET': 0,'BIND_CARRIER_MESSAGING_SERVICE': 0,'BIND_CARRIER_SERVICES': 0,'BIND_CHOOSER_TARGET_SERVICE': 0,'BIND_CONDITION_PROVIDER_SERVICE': 0,'BIND_CONNECTION_SERVICE': 0,'BIND_DEVICE_ADMIN': 0,'BIND_DIRECTORY_SEARCH': 0,'BIND_DREAM_SERVICE': 0,'BIND_INCALL_SERVICE': 0,'BIND_INPUT_METHOD': 0,'BIND_INTENT_FILTER_VERIFIER': 0,'BIND_JOB_SERVICE': 0,'BIND_KEYGUARD_APPWIDGET': 0,'BIND_MIDI_DEVICE_SERVICE': 0,'BIND_NFC_SERVICE': 0,'BIND_NOTIFICATION_LISTENER_SERVICE': 0,'BIND_NOTIFICATION_RANKER_SERVICE': 0,'BIND_PACKAGE_VERIFIER': 0,'BIND_PRINT_RECOMMENDATION_SERVICE': 0,'BIND_PRINT_SERVICE': 0,'BIND_PRINT_SPOOLER_SERVICE': 0,'BIND_QUICK_SETTINGS_TILE': 0,'BIND_REMOTEVIEWS': 0,'BIND_REMOTE_DISPLAY': 0,'BIND_ROUTE_PROVIDER': 0,'BIND_RUNTIME_PERMISSION_PRESENTER_SERVICE': 0,'BIND_SCREENING_SERVICE': 0,'BIND_TELECOM_CONNECTION_SERVICE': 0,'BIND_TEXT_SERVICE': 0,'BIND_TRUST_AGENT': 0,'BIND_TV_INPUT': 0,'BIND_TV_REMOTE_SERVICE': 0,'BIND_VOICE_INTERACTION': 0,'BIND_VPN_SERVICE': 0,'BIND_VR_LISTENER_SERVICE': 0,'BIND_WALLPAPER': 0,'BLUETOOTH': 0,'BLUETOOTH_ADMIN': 0,'BLUETOOTH_MAP': 0,'BLUETOOTH_PRIVILEGED': 0,'BLUETOOTH_STACK': 0,'BRICK': 0,'BROADCAST_CALLLOG_INFO': 0,'BROADCAST_NETWORK_PRIVILEGED': 0,'BROADCAST_PACKAGE_REMOVED': 0,'BROADCAST_PHONE_ACCOUNT_REGISTRATION': 0,'BROADCAST_SMS': 0,'BROADCAST_STICKY': 0,'BROADCAST_WAP_PUSH': 0,'CACHE_CONTENT': 0,'CALL_PRIVILEGED': 0,'CAMERA_DISABLE_TRANSMIT_LED': 0,'CAMERA_SEND_SYSTEM_EVENTS': 0,'CAPTURE_AUDIO_HOTWORD': 0,'CAPTURE_AUDIO_OUTPUT': 0,'CAPTURE_SECURE_VIDEO_OUTPUT': 0,'CAPTURE_TV_INPUT': 0,'CAPTURE_VIDEO_OUTPUT': 0,'CARRIER_FILTER_SMS': 0,'CHANGE_APP_IDLE_STATE': 0,'CHANGE_BACKGROUND_DATA_SETTING': 0,'CHANGE_COMPONENT_ENABLED_STATE': 0,'CHANGE_CONFIGURATION': 0,'CHANGE_DEVICE_IDLE_TEMP_WHITELIST': 0,'CHANGE_NETWORK_STATE': 0,'CHANGE_WIFI_MULTICAST_STATE': 0,'CHANGE_WIFI_STATE': 0,'CHANGE_WIMAX_STATE': 0,'CLEAR_APP_CACHE': 0,'CLEAR_APP_GRANTED_URI_PERMISSIONS': 0,'CLEAR_APP_USER_DATA': 0,'CONFIGURE_DISPLAY_COLOR_TRANSFORM': 0,'CONFIGURE_WIFI_DISPLAY': 0,'CONFIRM_FULL_BACKUP': 0,'CONNECTIVITY_INTERNAL': 0,'CONTROL_INCALL_EXPERIENCE': 0,'CONTROL_KEYGUARD': 0,'CONTROL_LOCATION_UPDATES': 0,'CONTROL_VPN': 0,'CONTROL_WIFI_DISPLAY': 0,'COPY_PROTECTED_DATA': 0,'CREATE_USERS': 0,'CRYPT_KEEPER': 0,'DELETE_CACHE_FILES': 0,'DELETE_PACKAGES': 0,'DEVICE_POWER': 0,'DIAGNOSTIC': 0,'DISABLE_KEYGUARD': 0,'DISPATCH_NFC_MESSAGE': 0,'DISPATCH_PROVISIONING_MESSAGE': 0,'DOWNLOAD_CACHE_NON_PURGEABLE': 0,'DUMP': 0,'DVB_DEVICE': 0,'EXPAND_STATUS_BAR': 0,'FACTORY_TEST': 0,'FILTER_EVENTS': 0,'FLASHLIGHT': 0,'FORCE_BACK': 0,'FORCE_STOP_PACKAGES': 0,'FRAME_STATS': 0,'FREEZE_SCREEN': 0,'GET_ACCOUNTS_PRIVILEGED': 0,'GET_APP_GRANTED_URI_PERMISSIONS': 0,'GET_APP_OPS_STATS': 0,'GET_DETAILED_TASKS': 0,'GET_INTENT_SENDER_INTENT': 0,'GET_PACKAGE_IMPORTANCE': 0,'GET_PACKAGE_SIZE': 0,'GET_PASSWORD': 0,'GET_PROCESS_STATE_AND_OOM_SCORE': 0,'GET_TASKS': 0,'GET_TOP_ACTIVITY_INFO': 0,'GLOBAL_SEARCH': 0,'GLOBAL_SEARCH_CONTROL': 0,'GRANT_RUNTIME_PERMISSIONS': 0,'HARDWARE_TEST': 0,'HDMI_CEC': 0,'INJECT_EVENTS': 0,'INSTALL_GRANT_RUNTIME_PERMISSIONS': 0,'INSTALL_LOCATION_PROVIDER': 0,'INSTALL_PACKAGES': 0,'INTENT_FILTER_VERIFICATION_AGENT': 0,'INTERACT_ACROSS_USERS': 0,'INTERACT_ACROSS_USERS_FULL': 0,'INTERNAL_SYSTEM_WINDOW': 0,'INTERNET': 0,'INVOKE_CARRIER_SETUP': 0,'KILL_BACKGROUND_PROCESSES': 0,'KILL_UID': 0,'LAUNCH_TRUST_AGENT_SETTINGS': 0,'LOCAL_MAC_ADDRESS': 0,'LOCATION_HARDWARE': 0,'LOOP_RADIO': 0,'MANAGE_ACCOUNTS': 0,'MANAGE_ACTIVITY_STACKS': 0,'MANAGE_APP_OPS_RESTRICTIONS': 0,'MANAGE_APP_TOKENS': 0,'MANAGE_CA_CERTIFICATES': 0,'MANAGE_DEVICE_ADMINS': 0,'MANAGE_DOCUMENTS': 0,'MANAGE_FINGERPRINT': 0,'MANAGE_MEDIA_PROJECTION': 0,'MANAGE_NETWORK_POLICY': 0,'MANAGE_NOTIFICATIONS': 0,'MANAGE_PROFILE_AND_DEVICE_OWNERS': 0,'MANAGE_SOUND_TRIGGER': 0,'MANAGE_USB': 0,'MANAGE_USERS': 0,'MANAGE_VOICE_KEYPHRASES': 0,'MASTER_CLEAR': 0,'MEDIA_CONTENT_CONTROL': 0,'MODIFY_APPWIDGET_BIND_PERMISSIONS': 0,'MODIFY_AUDIO_ROUTING': 0,'MODIFY_AUDIO_SETTINGS': 0,'MODIFY_CELL_BROADCASTS': 0,'MODIFY_DAY_NIGHT_MODE': 0,'MODIFY_NETWORK_ACCOUNTING': 0,'MODIFY_PARENTAL_CONTROLS': 0,'MODIFY_PHONE_STATE': 0,'MOUNT_FORMAT_FILESYSTEMS': 0,'MOUNT_UNMOUNT_FILESYSTEMS': 0,'MOVE_PACKAGE': 0,'NET_ADMIN': 0,'NET_TUNNELING': 0,'NFC': 0,'NFC_HANDOVER_STATUS': 0,'NOTIFY_PENDING_SYSTEM_UPDATE': 0,'OBSERVE_GRANT_REVOKE_PERMISSIONS': 0,'OEM_UNLOCK_STATE': 0,'OVERRIDE_WIFI_CONFIG': 0,'PACKAGE_USAGE_STATS': 0,'PACKAGE_VERIFICATION_AGENT': 0,'PACKET_KEEPALIVE_OFFLOAD': 0,'PEERS_MAC_ADDRESS': 0,'PERFORM_CDMA_PROVISIONING': 0,'PERFORM_SIM_ACTIVATION': 0,'PERSISTENT_ACTIVITY': 0,'PROCESS_CALLLOG_INFO': 0,'PROCESS_PHONE_ACCOUNT_REGISTRATION': 0,'PROVIDE_TRUST_AGENT': 0,'QUERY_DO_NOT_ASK_CREDENTIALS_ON_BOOT': 0,'READ_BLOCKED_NUMBERS': 0,'READ_DREAM_STATE': 0,'READ_FRAME_BUFFER': 0,'READ_INPUT_STATE': 0,'READ_INSTALL_SESSIONS': 0,'READ_LOGS': 0,'READ_NETWORK_USAGE_HISTORY': 0,'READ_OEM_UNLOCK_STATE': 0,'READ_PRECISE_PHONE_STATE': 0,'READ_PRIVILEGED_PHONE_STATE': 0,'READ_PROFILE': 0,'READ_SEARCH_INDEXABLES': 0,'READ_SOCIAL_STREAM': 0,'READ_SYNC_SETTINGS': 0,'READ_SYNC_STATS': 0,'READ_USER_DICTIONARY': 0,'READ_WIFI_CREDENTIAL': 0,'REAL_GET_TASKS': 0,'REBOOT': 0,'RECEIVE_BLUETOOTH_MAP': 0,'RECEIVE_BOOT_COMPLETED': 0,'RECEIVE_DATA_ACTIVITY_CHANGE': 0,'RECEIVE_EMERGENCY_BROADCAST': 0,'RECEIVE_MEDIA_RESOURCE_USAGE': 0,'RECEIVE_STK_COMMANDS': 0,'RECEIVE_WIFI_CREDENTIAL_CHANGE': 0,'RECOVERY': 0,'REGISTER_CALL_PROVIDER': 0,'REGISTER_CONNECTION_MANAGER': 0,'REGISTER_SIM_SUBSCRIPTION': 0,'REGISTER_WINDOW_MANAGER_LISTENERS': 0,'REMOTE_AUDIO_PLAYBACK': 0,'REMOVE_DRM_CERTIFICATES': 0,'REMOVE_TASKS': 0,'REORDER_TASKS': 0,'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS': 0,'REQUEST_INSTALL_PACKAGES': 0,'RESET_FINGERPRINT_LOCKOUT': 0,'RESET_SHORTCUT_MANAGER_THROTTLING': 0,'RESTART_PACKAGES': 0,'RETRIEVE_WINDOW_CONTENT': 0,'RETRIEVE_WINDOW_TOKEN': 0,'REVOKE_RUNTIME_PERMISSIONS': 0,'SCORE_NETWORKS': 0,'SEND_CALL_LOG_CHANGE': 0,'SEND_DOWNLOAD_COMPLETED_INTENTS': 0,'SEND_RESPOND_VIA_MESSAGE': 0,'SEND_SMS_NO_CONFIRMATION': 0,'SERIAL_PORT': 0,'SET_ACTIVITY_WATCHER': 0,'SET_ALWAYS_FINISH': 0,'SET_ANIMATION_SCALE': 0,'SET_DEBUG_APP': 0,'SET_INPUT_CALIBRATION': 0,'SET_KEYBOARD_LAYOUT': 0,'SET_ORIENTATION': 0,'SET_POINTER_SPEED': 0,'SET_PREFERRED_APPLICATIONS': 0,'SET_PROCESS_LIMIT': 0,'SET_SCREEN_COMPATIBILITY': 0,'SET_TIME': 0,'SET_TIME_ZONE': 0,'SET_WALLPAPER': 0,'SET_WALLPAPER_COMPONENT': 0,'SET_WALLPAPER_HINTS': 0,'SHUTDOWN': 0,'SIGNAL_PERSISTENT_PROCESSES': 0,'START_ANY_ACTIVITY': 0,'START_PRINT_SERVICE_CONFIG_ACTIVITY': 0,'START_TASKS_FROM_RECENTS': 0,'STATUS_BAR': 0,'STATUS_BAR_SERVICE': 0,'STOP_APP_SWITCHES': 0,'STORAGE_INTERNAL': 0,'SUBSCRIBED_FEEDS_READ': 0,'SUBSCRIBED_FEEDS_WRITE': 0,'SUBSTITUTE_NOTIFICATION_APP_NAME': 0,'SYSTEM_ALERT_WINDOW': 0,'TABLET_MODE': 0,'TEMPORARY_ENABLE_ACCESSIBILITY': 0,'TETHER_PRIVILEGED': 0,'TRANSMIT_IR': 0,'TRUST_LISTENER': 0,'TV_INPUT_HARDWARE': 0,'TV_VIRTUAL_REMOTE_CONTROLLER': 0,'UPDATE_APP_OPS_STATS': 0,'UPDATE_CONFIG': 0,'UPDATE_DEVICE_STATS': 0,'UPDATE_LOCK': 0,'UPDATE_LOCK_TASK_PACKAGES': 0,'USER_ACTIVITY': 0,'USE_CREDENTIALS': 0,'VIBRATE': 0,'WAKE_LOCK': 0,'WRITE_APN_SETTINGS': 0,'WRITE_BLOCKED_NUMBERS': 0,'WRITE_DREAM_STATE': 0,'WRITE_GSERVICES': 0,'WRITE_MEDIA_STORAGE': 0,'WRITE_PROFILE': 0,'WRITE_SECURE_SETTINGS': 0,'WRITE_SETTINGS': 0,'WRITE_SMS': 0,'WRITE_SOCIAL_STREAM': 0,'WRITE_SYNC_SETTINGS': 0,'WRITE_USER_DICTIONARY' : 0}

        global var_perm_accept_handover
        global var_perm_access_background_location
        global var_perm_access_blobs_across_users
        global var_perm_access_checkin_properties
        global var_perm_access_coarse_location
        global var_perm_access_fine_location
        global var_perm_access_location_extra_commands
        global var_perm_access_media_location
        global var_perm_access_network_state
        global var_perm_access_notification_policy
        global var_perm_access_wifi_state
        global var_perm_add_voicemail
        global var_perm_account_manager
        global var_perm_activity_recognition
        global var_perm_answer_phone_calls
        global var_perm_battery_stats
        global var_perm_bind_accessibility_service
        global var_perm_bind_appwidget
        global var_perm_bind_autofill_service
        global var_perm_bind_call_redirection_service
        global var_perm_bind_carrier_messaging_client_service
        global var_perm_bind_carrier_messaging_service
        global var_perm_bind_carrier_services
        global var_perm_bind_chooser_target_service
        global var_perm_bind_companion_device_service
        global var_perm_bind_condition_provider_service
        global var_perm_bind_controls
        global var_perm_bind_device_admin
        global var_perm_bind_dream_service
        global var_perm_bind_incall_service
        global var_perm_bind_input_method
        global var_perm_bind_midi_device_service
        global var_perm_bind_nfc_service
        global var_perm_bind_notification_listener_service
        global var_perm_bind_print_service
        global var_perm_bind_quick_access_wallet_service
        global var_perm_bind_quick_settings_tile
        global var_perm_bind_remoteviews
        global var_perm_bind_screening_service
        global var_perm_bind_telecom_connection_service
        global var_perm_bind_text_service
        global var_perm_bind_tv_input
        global var_perm_bind_visual_voicemail_service
        global var_perm_bind_voice_interaction
        global var_perm_bind_vpn_service
        global var_perm_bind_vr_listener_service
        global var_perm_bluetooth
        global var_perm_bluetooth_admin
        global var_perm_bluetooth_advertise
        global var_perm_bluetooth_connect
        global var_perm_bluetooth_privileged
        global var_perm_bluetooth_scan
        global var_perm_body_sensors
        global var_perm_broadcast_package_removed
        global var_perm_broadcast_sms
        global var_perm_broadcast_sticky
        global var_perm_broadcast_wap_push
        global var_perm_call_companion_app
        global var_perm_call_phone
        global var_perm_call_privileged
        global var_perm_camera
        global var_perm_capture_audio_output
        global var_perm_change_component_enabled_state
        global var_perm_change_configuration
        global var_perm_change_network_state
        global var_perm_change_wifi_multicast_state
        global var_perm_change_wifi_state
        global var_perm_clear_app_cache
        global var_perm_control_location_updates
        global var_perm_delete_cache_files
        global var_perm_delete_packages
        global var_perm_diagnostic
        global var_perm_disable_keyguard
        global var_perm_expand_status_bar
        global var_perm_factory_test
        global var_perm_foreground_service
        global var_perm_get_accounts
        global var_perm_get_accounts_privileged
        global var_perm_get_tasks
        global var_perm_global_search
        global var_perm_hide_overlay_windows
        global var_perm_high_sampling_rate_sensors
        global var_perm_install_location_provider
        global var_perm_install_packages
        global var_perm_install_shortcut
        global var_perm_instant_app_foreground_service
        global var_perm_interact_across_profiles
        global var_perm_internet
        global var_perm_kill_background_processes
        global var_perm_loader_usage_stats
        global var_perm_location_hardware
        global var_perm_manage_documents
        global var_perm_manage_external_storage
        global var_perm_manage_media
        global var_perm_manage_ongoing_calls
        global var_perm_manage_own_calls
        global var_perm_master_clear
        global var_perm_media_content_control
        global var_perm_modify_audio_settings
        global var_perm_modify_phone_state
        global var_perm_mount_format_filesystems
        global var_perm_mount_unmount_filesystems
        global var_perm_nfc
        global var_perm_nfc_preferred_payment_info
        global var_perm_nfc_transaction_event
        global var_perm_package_usage_stats
        global var_perm_persistent_activity
        global var_perm_process_outgoing_calls
        global var_perm_query_all_packages
        global var_perm_read_calendar
        global var_perm_read_call_log
        global var_perm_read_contacts
        global var_perm_read_external_storage
        global var_perm_read_input_state
        global var_perm_read_logs
        global var_perm_read_phone_numbers
        global var_perm_read_phone_state
        global var_perm_read_precise_phone_state
        global var_perm_read_sms
        global var_perm_read_sync_settings
        global var_perm_read_sync_stats
        global var_perm_read_voicemail
        global var_perm_reboot
        global var_perm_receive_boot_completed
        global var_perm_receive_mms
        global var_perm_receive_sms
        global var_perm_receive_wap_push
        global var_perm_record_audio
        global var_perm_reorder_tasks
        global var_perm_request_companion_profile_watch
        global var_perm_request_companion_run_in_background
        global var_perm_request_companion_start_foreground_services_from_background
        global var_perm_request_companion_use_data_in_background
        global var_perm_request_delete_packages
        global var_perm_request_ignore_battery_optimizations
        global var_perm_request_install_packages
        global var_perm_request_observe_companion_device_presence
        global var_perm_request_password_complexity
        global var_perm_restart_packages
        global var_perm_schedule_exact_alarm
        global var_perm_send_respond_via_message
        global var_perm_send_sms
        global var_perm_set_alarm
        global var_perm_set_always_finish
        global var_perm_set_animation_scale
        global var_perm_set_debug_app
        global var_perm_set_preferred_applications
        global var_perm_set_process_limit
        global var_perm_set_time
        global var_perm_set_time_zone
        global var_perm_set_wallpaper
        global var_perm_set_wallpaper_hints
        global var_perm_signal_persistent_processes
        global var_perm_sms_financial_transactions
        global var_perm_start_foreground_services_from_background
        global var_perm_start_view_permission_usage
        global var_perm_status_bar
        global var_perm_system_alert_window
        global var_perm_transmit_ir
        global var_perm_uninstall_shortcut
        global var_perm_update_device_stats
        global var_perm_update_packages_without_user_action
        global var_perm_use_biometric
        global var_perm_use_fingerprint
        global var_perm_use_full_screen_intent
        global var_perm_use_icc_auth_with_device_identifier
        global var_perm_use_sip
        global var_perm_uwb_ranging
        global var_perm_vibrate
        global var_perm_wake_lock
        global var_perm_write_apn_settings
        global var_perm_write_calendar
        global var_perm_write_call_log
        global var_perm_write_contacts
        global var_perm_write_external_storage
        global var_perm_write_gservices
        global var_perm_write_secure_settings
        global var_perm_write_settings
        global var_perm_write_sync_settings
        global var_perm_write_voicemail
        global var_perm_bind_wallpaper
        global var_perm_dump
        global var_perm_get_package_size
        global var_perm_launch_two_pane_settings_deep_link
        global dict_contained_libraries
        global dict_arch_support
        global dict_arm64_libaries
        global dict_arm64_lib_md5
        global dict_arm64_lib_sha256
        global dict_arm32_libaries
        global dict_arm32_lib_md5
        global dict_arm32_lib_sha256
        global dict_x86_libaries
        global dict_x86_lib_md5
        global dict_x86_lib_sha256
        global dict_x64_libaries
        global dict_x64_lib_md5
        global dict_x64_lib_sha256
        global dict_contained_assets
        global dict_contained_assets_md5
        global dict_contained_assets_sha256
        global dict_directory_listing
        global dict_directory_file_listing
        global dict_ssdeep_so_output
        global apk_md5_hash
        global apk_sha1_hash
        global apk_sha256_hash
        global apk_sha512_hash
        global cert_content_extract_subject
        global cert_content_extract_serial

        var_perm_launch_two_pane_settings_deep_link = 0
        var_perm_get_package_size = 0
        var_perm_dump = 0
        var_perm_bind_wallpaper = 0
        var_perm_accept_handover = 0 
        var_perm_access_background_location = 0 
        var_perm_access_blobs_across_users = 0 
        var_perm_access_checkin_properties = 0 
        var_perm_access_coarse_location = 0 
        var_perm_access_fine_location = 0 
        var_perm_access_location_extra_commands = 0 
        var_perm_access_media_location = 0 
        var_perm_access_network_state = 0 
        var_perm_access_notification_policy = 0 
        var_perm_access_wifi_state = 0 
        var_perm_add_voicemail = 0 
        var_perm_account_manager = 0 
        var_perm_activity_recognition = 0 
        var_perm_answer_phone_calls = 0 
        var_perm_battery_stats = 0 
        var_perm_bind_accessibility_service = 0 
        var_perm_bind_appwidget = 0 
        var_perm_bind_autofill_service = 0 
        var_perm_bind_call_redirection_service = 0 
        var_perm_bind_carrier_messaging_client_service = 0 
        var_perm_bind_carrier_messaging_service = 0 
        var_perm_bind_carrier_services = 0 
        var_perm_bind_chooser_target_service = 0 
        var_perm_bind_companion_device_service = 0 
        var_perm_bind_condition_provider_service = 0 
        var_perm_bind_controls = 0 
        var_perm_bind_device_admin = 0 
        var_perm_bind_dream_service = 0 
        var_perm_bind_incall_service = 0 
        var_perm_bind_input_method = 0 
        var_perm_bind_midi_device_service = 0 
        var_perm_bind_nfc_service = 0 
        var_perm_bind_notification_listener_service = 0 
        var_perm_bind_print_service = 0 
        var_perm_bind_quick_access_wallet_service = 0 
        var_perm_bind_quick_settings_tile = 0 
        var_perm_bind_remoteviews = 0 
        var_perm_bind_screening_service = 0 
        var_perm_bind_telecom_connection_service = 0 
        var_perm_bind_text_service = 0 
        var_perm_bind_tv_input = 0 
        var_perm_bind_visual_voicemail_service = 0 
        var_perm_bind_voice_interaction = 0 
        var_perm_bind_vpn_service = 0 
        var_perm_bind_vr_listener_service = 0 
        var_perm_bluetooth = 0 
        var_perm_bluetooth_admin = 0 
        var_perm_bluetooth_advertise = 0 
        var_perm_bluetooth_connect = 0 
        var_perm_bluetooth_privileged = 0 
        var_perm_bluetooth_scan = 0 
        var_perm_body_sensors = 0 
        var_perm_broadcast_package_removed = 0 
        var_perm_broadcast_sms = 0 
        var_perm_broadcast_sticky = 0 
        var_perm_broadcast_wap_push = 0 
        var_perm_call_companion_app = 0 
        var_perm_call_phone = 0 
        var_perm_call_privileged = 0 
        var_perm_camera = 0 
        var_perm_capture_audio_output = 0 
        var_perm_change_component_enabled_state = 0 
        var_perm_change_configuration = 0 
        var_perm_change_network_state = 0 
        var_perm_change_wifi_multicast_state = 0 
        var_perm_change_wifi_state = 0 
        var_perm_clear_app_cache = 0 
        var_perm_control_location_updates = 0 
        var_perm_delete_cache_files = 0 
        var_perm_delete_packages = 0 
        var_perm_diagnostic = 0 
        var_perm_disable_keyguard = 0 
        var_perm_expand_status_bar = 0 
        var_perm_factory_test = 0 
        var_perm_foreground_service = 0 
        var_perm_get_accounts = 0 
        var_perm_get_accounts_privileged = 0 
        var_perm_get_tasks = 0 
        var_perm_global_search = 0 
        var_perm_hide_overlay_windows = 0 
        var_perm_high_sampling_rate_sensors = 0 
        var_perm_install_location_provider = 0 
        var_perm_install_packages = 0 
        var_perm_install_shortcut = 0 
        var_perm_instant_app_foreground_service = 0 
        var_perm_interact_across_profiles = 0 
        var_perm_internet = 0 
        var_perm_kill_background_processes = 0 
        var_perm_loader_usage_stats = 0 
        var_perm_location_hardware = 0 
        var_perm_manage_documents = 0 
        var_perm_manage_external_storage = 0 
        var_perm_manage_media = 0 
        var_perm_manage_ongoing_calls = 0 
        var_perm_manage_own_calls = 0 
        var_perm_master_clear = 0 
        var_perm_media_content_control = 0 
        var_perm_modify_audio_settings = 0 
        var_perm_modify_phone_state = 0 
        var_perm_mount_format_filesystems = 0 
        var_perm_mount_unmount_filesystems = 0 
        var_perm_nfc = 0 
        var_perm_nfc_preferred_payment_info = 0 
        var_perm_nfc_transaction_event = 0 
        var_perm_package_usage_stats = 0 
        var_perm_persistent_activity = 0 
        var_perm_process_outgoing_calls = 0 
        var_perm_query_all_packages = 0 
        var_perm_read_calendar = 0 
        var_perm_read_call_log = 0 
        var_perm_read_contacts = 0 
        var_perm_read_external_storage = 0 
        var_perm_read_input_state = 0 
        var_perm_read_logs = 0 
        var_perm_read_phone_numbers = 0 
        var_perm_read_phone_state = 0 
        var_perm_read_precise_phone_state = 0 
        var_perm_read_sms = 0 
        var_perm_read_sync_settings = 0 
        var_perm_read_sync_stats = 0 
        var_perm_read_voicemail = 0 
        var_perm_reboot = 0 
        var_perm_receive_boot_completed = 0 
        var_perm_receive_mms = 0 
        var_perm_receive_sms = 0 
        var_perm_receive_wap_push = 0 
        var_perm_record_audio = 0 
        var_perm_reorder_tasks = 0 
        var_perm_request_companion_profile_watch = 0 
        var_perm_request_companion_run_in_background = 0 
        var_perm_request_companion_start_foreground_services_from_background = 0 
        var_perm_request_companion_use_data_in_background = 0 
        var_perm_request_delete_packages = 0 
        var_perm_request_ignore_battery_optimizations = 0 
        var_perm_request_install_packages = 0 
        var_perm_request_observe_companion_device_presence = 0 
        var_perm_request_password_complexity = 0 
        var_perm_restart_packages = 0 
        var_perm_schedule_exact_alarm = 0 
        var_perm_send_respond_via_message = 0 
        var_perm_send_sms = 0 
        var_perm_set_alarm = 0 
        var_perm_set_always_finish = 0 
        var_perm_set_animation_scale = 0 
        var_perm_set_debug_app = 0 
        var_perm_set_preferred_applications = 0 
        var_perm_set_process_limit = 0 
        var_perm_set_time = 0 
        var_perm_set_time_zone = 0 
        var_perm_set_wallpaper = 0 
        var_perm_set_wallpaper_hints = 0 
        var_perm_signal_persistent_processes = 0 
        var_perm_sms_financial_transactions = 0 
        var_perm_start_foreground_services_from_background = 0 
        var_perm_start_view_permission_usage = 0 
        var_perm_status_bar = 0 
        var_perm_system_alert_window = 0 
        var_perm_transmit_ir = 0 
        var_perm_uninstall_shortcut = 0 
        var_perm_update_device_stats = 0 
        var_perm_update_packages_without_user_action = 0 
        var_perm_use_biometric = 0 
        var_perm_use_fingerprint = 0 
        var_perm_use_full_screen_intent = 0 
        var_perm_use_icc_auth_with_device_identifier = 0 
        var_perm_use_sip = 0 
        var_perm_uwb_ranging = 0 
        var_perm_vibrate = 0 
        var_perm_wake_lock = 0 
        var_perm_write_apn_settings = 0 
        var_perm_write_calendar = 0 
        var_perm_write_call_log = 0 
        var_perm_write_contacts = 0 
        var_perm_write_external_storage = 0 
        var_perm_write_gservices = 0 
        var_perm_write_secure_settings = 0 
        var_perm_write_settings = 0 
        var_perm_write_sync_settings = 0 
        var_perm_write_voicemail = 0	
        dict_contained_libraries = ['']
        dict_arch_support = ['']
        dict_arm64_libaries = ['']
        dict_arm64_lib_md5 = ['']
        dict_arm64_lib_sha256 = ['']
        dict_arm32_libaries = ['']
        dict_arm32_lib_md5 = ['']
        dict_arm32_lib_sha256 = ['']
        dict_x86_libaries = ['']
        dict_x86_lib_md5 = ['']
        dict_x86_lib_sha256 = ['']
        dict_x64_libaries = ['']
        dict_x64_lib_md5 = ['']
        dict_x64_lib_sha256 = ['']
        dict_contained_assets = ['']
        dict_contained_assets_md5 = ['']
        dict_contained_assets_sha256 = ['']
        dict_directory_listing = ['']
        dict_directory_file_listing = ['']
        dict_ssdeep_so_output = ['']
        cert_content_extract_subject = ''
        cert_content_extract_serial = ''

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
                log_txt_update.write("[INFO]: Starting YARA Pattern Match of: " + apk_full_path + ".\n")   
            if arg_verbose_output == 1:
                print("")
                print("[YARA] #################################### YARA Pattern Match STARTED ####################################")
                print("")
                print("[YARA]: Started YARA Pattern Match within: " + apk_full_path + ".")                                                               
            try:
                var_yara_decomp = "\"" + apk_decomp_directory + "\\" + apk + "yara" + "\"" + " "
                
                yara_apk_full_path = "\"" + apk_full_path + "\""
                var_yara_command = '.\\win\\yara64.exe -s -S -m ' + ' ".\\yara\\master_index.yar" ' + jadx_dex_full_path
                var_yara_command_split = var_yara_command.split()
                subprocess.check_call(var_yara_command, stdout=var_yara_log_write_txt_up)
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
######################################################## Manifest Analysis Function ####################################################
########################################################################################################################################    

        func_permission_checks()

########################################################################################################################################
########################################################## SO FINDER FUNCTION CALL #####################################################
########################################################################################################################################    

        func_so_finder_within_apk_ripper()

########################################################################################################################################
############################################################# JSON Build Call  #########################################################
########################################################################################################################################

        func_apk_json_map()

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
###               Copyright (C)  2025  s3raph                             #
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
