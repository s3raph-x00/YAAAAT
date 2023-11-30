########################################################################################################################################
#################################################### Author:      s3raph                ################################################
#################################################### Purpose:     To Pass the Butter    ################################################
#################################################### Version:     .01055                ################################################
#################################################### Last Update: 20220906              ################################################
########################################################################################################################################

import sys
import platform
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
    print("                            @   @  @@@@@@  @@@@@@@  @@@  @@@      @@@@@@@  @@@ @@@@@@@  @@@@@@@  @@@@@@@@ @@@@@@@ ")
    print("                             @ @  @@!  @@@ @@!  @@@ @@!  !@@      @@!  @@@ @@! @@!  @@@ @@!  @@@ @@!      @@!  @@@")
    print("                              @   @!@!@!@! @!@@!@!  @!@@!@!       @!@!!@!  !!@ @!@@!@!  @!@@!@!  @!!!:!   @!@!!@! ")
    print("                             @ !  !!:  !!! !!:      !!: :!!       !!: :!!  !!: !!:      !!:      !!:      !!: :!! ")
    print("                            !  ::  :   : :  :        :   :::       :   : : :    :        :       : :: :::  :   : :")

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
        log_txt_update.write("--- YAAAAT xAPK Ripper ---\n")
        log_txt_update.write("[LOG]: Tool Started on: " + timestr_case + " at " + timestr_dir + "\n")  

def randomFunction():
    return "import sys; print(sys.argv[1]); input('Press Enter..')"

def func_command_call():
########################################################################################################################################
############################################################ Command Call Creation #####################################################
########################################################################################################################################
    global var_proc_call_xapk_apk_ripper_dir_main
    var_proc_call_xapk_apk_ripper_dir_main = xapk_extract_directory
    #var_proc_call_xapk_apk_ripper_dir_main = var_proc_call_xapk_apk_ripper_dir_main.replace('\\', '\\\\')
    var_proc_call_xapk_apk_ripper_dir_main = "\"" + var_proc_call_xapk_apk_ripper_dir_main + "\\" + "\""
    if script_ext_location_check == 0:
        if var_forensic_case_bool == 1:
            log_txt_update.write("[WARN]: xAPK extraction location check returned 0, not running APK Ripper." + "\n")
        if arg_verbose_output == 1:
            print("[WARN]: xAPK extraction location check returned 0, not running APK Ripper.")
        return
    if script_ext_location_check == 1:
        if platform.system() == "Windows":
            var_core_command = "cmd.exe /c python ./YAAAAT_1_apk_ripper.py "
            if arg_custom_search == 2:
                if arg_string_file_search != "":
                    var_core_command = var_core_command + " " + "-S " + arg_string_file_search + " "
                else:
                    if var_forensic_case_bool == 1:
                        log_txt_update.write("[ERROR]: Variable with file location containing strings to search xapk(s) for is blank. This should not happen :(." + "\n")
                    if arg_verbose_output == 1:
                        print("[ERROR]: Variable with file location containing strings to search xapk(s) for is blank. This should not happen :(.")
            if var_yara_flag == 1:
                var_core_command = var_core_command + " " + "-y "
            if arg_custom_search == 1:
                if arg_string_search != "":
                    var_core_command = var_core_command + " " + "-s " + arg_string_search + " "
            if arg_debug_output == 1:
                var_core_command = var_core_command + " " + "-r "
            if var_forensic_case_bool == 1:
                var_core_command = var_core_command + " " + "-l "
            if arg_gucci_output == 1:
                var_core_command = var_core_command + " " + "-g "
            if arg_verbose_output == 1:
                var_core_command = var_core_command + " " + "-v "
            if arg_autopsy_plugin == 1:
                var_core_command = var_core_command + " " + "-a "
            if var_output_directory_empty != "":
                var_core_command = var_core_command + " " + "-o " + var_output_directory
            var_core_command = var_core_command + " -i "  + var_proc_call_xapk_apk_ripper_dir_main
            if var_forensic_case_bool == 1:
                log_txt_update.write("[LOG]: CLI passing the following command to xAPK Ripper: " + var_core_command + "\n")
            if arg_verbose_output == 1:
                print("[LOG]: xAPK Ripper passing the following command to APK Ripper: " + var_core_command)
            var_command_setup_split = var_core_command.split()
        else:  
            var_command_setup_split = "x-terminal-emulator -e".split()
        echo = [sys.executable, "-c",randomFunction()
                ]
        processes = [Popen(var_core_command)]
        for proc in processes:
            proc.wait()

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

def func_fileheader_check():
########################################################################################################################################
############################################################ Fileheader Function #######################################################
########################################################################################################################################

    global xapk_file_header_check
    global xapk_file_header_check_data
    global xapk_file_header_sig
    global xapk_extract_continue
    
    xapk_file_header_check = open(xapk_full_path, "rb")
    xapk_file_header_check_data = xapk_file_header_check.read(2)
    xapk_file_header_sig = "PK"

    xapk_extract_continue = 0
        
    if xapk_file_header_sig in xapk_file_header_check_data:
        xapk_extract_continue = 1
        xapk_file_header_check.close()
        if var_forensic_case_bool == 1:
            log_txt_update.write("[HEADER]: File Header: " + xapk_full_path + " matches that of an xAPK.\n")
        if arg_verbose_output == 1:
            print("[HEADER]: File Header: " + xapk_full_path + " matches that of an xAPK.")

    else:
        xapk_file_header_check.close()
        if var_forensic_case_bool == 1:
            log_txt_update.write("[HEADER] File Header: " + xapk_full_path + " does not match that of an xAPK. Skipping Processing.\n")
        if arg_verbose_output == 1:
            print("[HEADER] File Header: " + xapk_full_path + " does not match that of an xAPK. Skipping Processing.")

def func_hash_all_files():
########################################################################################################################################
####################################################### Hash Extracted Files Function ##################################################
########################################################################################################################################
    global var_embed_file_hits
    var_embed_file_hits = 0
    for var_path, var_directory, var_files in os.walk(os.path.abspath(xapk_extract_directory)):
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

def func_json_manifest_process():
########################################################################################################################################
###################################################### Process JSON Manifest Function ##################################################
########################################################################################################################################
    for var_manifest_permission in (var_raw_json_manifest['permissions']):
        var_manifest_info_write = ("[Mainfest]: Reported Required Permissions: " + var_manifest_permission + "\n")
        mani_unproc_write_txt_update.write(var_manifest_info_write)
        if arg_verbose_output == 1:
            print("[Mainfest]: Reported Required Permissions: " + var_manifest_permission)
    for var_manifest_embed_apk in (var_raw_json_manifest['split_apks']):
        var_manifest_info_write = ("[Mainfest]: Embedded APK File Name: " + var_manifest_embed_apk['file'] + "\n")
        mani_unproc_write_txt_update.write(var_manifest_info_write)
        if arg_verbose_output == 1:
            print("[Mainfest]: Embedded APK File Name: " + var_manifest_embed_apk['file'])
    
    var_manifest_info_write = ("[Mainfest]: Reported Package Name: " + var_raw_json_manifest['package_name'] + "\n")
    mani_unproc_write_txt_update.write(var_manifest_info_write)
    var_manifest_info_write = ("[Mainfest]: xAPK version: " + str(var_raw_json_manifest['xapk_version']) + "\n")
    mani_unproc_write_txt_update.write(var_manifest_info_write)
    var_manifest_info_write = ("[Mainfest]: Minimum SDK Version: " + str(var_raw_json_manifest['min_sdk_version']) + "\n")
    mani_unproc_write_txt_update.write(var_manifest_info_write)
    var_manifest_info_write = ("[Mainfest]: Target SDK Version: " + str(var_raw_json_manifest['target_sdk_version']) + "\n")
    mani_unproc_write_txt_update.write(var_manifest_info_write)
    var_manifest_info_write = ("[Mainfest]: Reported Total Size: " + str(((var_raw_json_manifest['total_size'])/1024)/1024) + "MB" + "\n")
    mani_unproc_write_txt_update.write(var_manifest_info_write)
    var_manifest_info_write = ("[Mainfest]: Reported Application Version: " + str(var_raw_json_manifest['version_code']) + "\n")
    mani_unproc_write_txt_update.write(var_manifest_info_write)

    if arg_verbose_output == 1:    
        print("[Mainfest]: Reported Package Name: " + var_raw_json_manifest['package_name'])
        print("[Mainfest]: xAPK version: " + str(var_raw_json_manifest['xapk_version']))
        print("[Mainfest]: Minimum SDK Version: " + str(var_raw_json_manifest['min_sdk_version']))    
        print("[Mainfest]: Target SDK Version: " + str(var_raw_json_manifest['target_sdk_version']))
        print("[Mainfest]: Reported Total Size: " + str(((var_raw_json_manifest['total_size'])/1024)/1024) + "MB")
        print("[Mainfest]: Reported Application Version: " + str(var_raw_json_manifest['version_code']))
    
    
def func_json_manifest_rip():
########################################################################################################################################
######################################################## JSON Manifest Rip Function ####################################################
########################################################################################################################################
    global var_raw_json_manifest
    global var_json_manifest_file
    global var_json_ripper_flag
    global json_full_path
    
    var_json_ripper_flag = 0
    
    directory_search_pattern_json = (var_proc_call_xapk_apk_ripper_dir+"\\*.json")
    if var_forensic_case_bool == 1:
        log_txt_update.write("[INFO]: Searching for JSON files in: " + directory_search_pattern_json + "\n")
    if arg_verbose_output == 1:
        print("[INFO]: Searching for JSON files in: " + directory_search_pattern_json)

    for json_full_path in glob.glob(directory_search_pattern_json):
        if json_full_path != '':
            var_json_manifest_file = open(json_full_path)
            if arg_verbose_output == 1:
                print("[INFO]: Found JSON file: " + json_full_path)
            if var_forensic_case_bool == 1:
                log_txt_update.write("[INFO]: Found JSON file: " + json_full_path + "\n")
            if var_json_manifest_file != '':
                var_raw_json_manifest = json.load(var_json_manifest_file)
                var_json_manifest_file.close
                func_json_manifest_process()

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
    global xapk
    global arg_debug_output
    global arg_string_search
    global arg_string_file_search
    global arg_custom_search
    global var_sys_complete_flag
    global var_py_complete_flag
    global var_yara_flag
    global file_txt_update
    global file_hashes_post_zip_extract_update
    global file_hashes_post_zip_extract
    global hashes_file_dump_txt
    global var_apk_ripper_flag
    global var_output_directory_empty
    global inputdirectory_var
    global xapk_full_path

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
    var_apk_ripper_flag = 0
    var_output_directory_empty = ''

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
        print("YAAAAT_xapk_ripper.py -i <Directory_To_Scan_For_xAPKs>")
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
            print("YAAAAT_xapk_ripper.py -i <Directory_To_Scan_For_xAPKs>")
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
        print("YAAAAT_xapk_ripper.py -i <Directory_To_Scan_For_xAPKs>")
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
    var_output_directory = var_output_directory.replace('\"', '') + "\\"	
    func_gu_st()
    func_python_version_check()

########################################################################################################################################
########################################################## CASE DIRECTORY CREATION #####################################################
########################################################################################################################################
    
    print("########################################################################################################################################")
    print("######################################################## RIPPER STARTED AT: " + timestr_dir + " ###################################################")
    print("########################################################################################################################################")
    print("")

    if var_output_directory == '':
        var_output_directory = inputdirectory
        print("[INFO]: Output Directory is: " + var_output_directory)
    else:
        var_output_directory_empty = var_output_directory
        print("[INFO]: Output Directory is: " + var_output_directory)

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
################################################################ xAPK SEARCH ###########################################################
########################################################################################################################################
    
    directory_search_pattern_check = (inputdirectory + "\\xapk_storage\\")
    if os.path.isdir(directory_search_pattern_check):
        directory_search_pattern = (inputdirectory + "\\xapk_storage\\*.xapk")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Searching for xAPKs in: " + directory_search_pattern + "\n")
        if arg_verbose_output == 1:
            print("[INFO]: Searching for xAPKs in: " + directory_search_pattern)
            print("")

    else:
        directory_search_pattern = (inputdirectory+"\\*.xapk")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Searching for xAPKs in: " + directory_search_pattern + "\n")
        if arg_verbose_output == 1:
            print("[INFO]: Searching for xAPKs in: " + directory_search_pattern)

    for xapk_full_path in glob.glob(directory_search_pattern):
        func_fileheader_check()
        if xapk_extract_continue == 0:
            continue
        if arg_verbose_output == 1:
            print("")
            print("############################################ RIPPING OF xAPK: " + os.path.basename(xapk_full_path) + " STARTED. ##############################")
            print("")
        xapk_with_extension = os.path.basename(xapk_full_path)
        xapk, discard_ext = os.path.splitext(xapk_with_extension)
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Found The xAPK: " + xapk_with_extension + " - Processing Now\n")
        if arg_verbose_output == 1:
            print("[INFO]: Found The xAPK: " + xapk_with_extension + " - Processing Now")

########################################################################################################################################
####################################################### EXTRACTION DIRECTORY CREATION ##################################################
########################################################################################################################################
        global xapk_main_pre_dir
        xapk_main_pre_dir = var_output_directory + "\\xapk_post_run\\"
        try:
            os.mkdir(xapk_main_pre_dir)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making xAPK Results Directory: " + xapk_main_pre_dir + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making xAPK Results Directory: " + xapk_main_pre_dir + ". Directory likely exists.")

        global xapk_main_dir
        xapk_main_dir = xapk_main_pre_dir + "\\" + timestr_dir
        try:
            os.mkdir(xapk_main_dir)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making xAPK Results Directory: " + xapk_main_dir + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making xAPK Results Directory: " + xapk_main_dir + ". Directory likely exists.")

        global xapk_main_dir_xapk
        xapk_main_dir_xapk = xapk_main_dir + "\\" + xapk
        try:
            os.mkdir(xapk_main_dir_xapk)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making xAPK Results Directory: " + xapk_main_dir_xapk + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making xAPK Results Directory: " + xapk_main_dir_xapk + ". Directory likely exists.")

        global xapk_source_directory
        xapk_source_directory = xapk_main_dir_xapk + "\\" + "_0_source"
        try:
            os.mkdir(xapk_source_directory)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making xAPK Results Directory: " + xapk_source_directory + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making xAPK Results Directory: " + xapk_source_directory + ". Directory likely exists.")

        global xapk_decomp_directory
        xapk_decomp_directory = xapk_main_dir_xapk + "\\" + "_1_decomp"
        try:
            os.mkdir(xapk_decomp_directory)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making xAPK Results Directory: " + xapk_decomp_directory + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making xAPK Results Directory: " + xapk_decomp_directory + ". Directory likely exists.")

        global xapk_results_directory
        xapk_results_directory = xapk_main_dir_xapk + "\\" + "_1_results"
        try:
            os.mkdir(xapk_results_directory)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making xAPK Results Directory: " + xapk_results_directory + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making xAPK Results Directory: " + xapk_results_directory + ". Directory likely exists.")
                
        global xapk_extract_directory
        xapk_extract_directory = xapk_main_dir_xapk + "\\" + "_2_extract"
        try:
            os.mkdir(xapk_extract_directory)
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Making xAPK Results Directory: " + xapk_extract_directory + ". Directory likely exists.\n")
            if arg_verbose_output == 1:
                print("[WARN]: Error Making xAPK Results Directory: " + xapk_extract_directory + ". Directory likely exists.")
        
        if arg_autopsy_plugin == 1:
            var_information_true_filename = xapk_with_extension[9:]
        else:
            var_information_true_filename = xapk_with_extension

        hashes_file_dump_txt = xapk_results_directory + "\\" + xapk + "_hash_info.txt"
        file_txt_update = open(hashes_file_dump_txt, "a")
        file_hashes_post_zip_extract = xapk_results_directory + "\\" + xapk + "_hash_extract.txt"
        file_hashes_post_zip_extract_update = open(file_hashes_post_zip_extract, "a")

########################################################################################################################################
################################################## EXTRACTION FILE DEFINITION AND CREATION #############################################
########################################################################################################################################

        global count_stats_write_txt
        global var_yara_log_txt
        global mani_unproc_write_txt
        
        count_stats_write_txt = xapk_results_directory + "\\" + xapk + "_stats.txt"
        mani_unproc_write_txt = xapk_results_directory + "\\" + xapk + "_manifest_info_unproc.txt"
        var_yara_log_txt = xapk_results_directory + "\\" + xapk + "_yara_hits.txt"
        
        global count_stats_write_txt_up
        global var_yara_log_write_txt_up
        global mani_unproc_write_txt_update  
        
        count_stats_write_txt_up = open(count_stats_write_txt, "a")
        mani_unproc_write_txt_update = open(mani_unproc_write_txt, "a")
        var_yara_log_write_txt_up = open(var_yara_log_txt, "a")

        var_information_filename_write = ("[INFO]: True xAPK Filename is: " + var_information_true_filename + "\n")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: True xAPK Filename is: " + var_information_true_filename + "\n")
        if arg_verbose_output == 1:
            print("[INFO]: True xAPK Filename is: " + var_information_true_filename)

########################################################################################################################################
########################################################## xAPK HASHING FUNCTIONS ######################################################
########################################################################################################################################

        md5_hash = hashlib.md5()
        with open(xapk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                md5_hash.update(byte_block)
            xapk_md5_hash = md5_hash.hexdigest()
            var_information_md5hash_write = ("[HASH]: MD5 Hash for: " + xapk + ".xapk is: " + xapk_md5_hash + "\n")
            file_txt_update.write(var_information_md5hash_write)

        sha1_hash = hashlib.sha1()
        with open(xapk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha1_hash.update(byte_block)
            xapk_sha1_hash = sha1_hash.hexdigest()
            var_information_sha1hash_write = ("[HASH]: SHA1 Hash for: " + xapk + ".xapk is: " + xapk_sha1_hash + "\n")
            file_txt_update.write(var_information_sha1hash_write)

        sha256_hash = hashlib.sha256()
        with open(xapk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            xapk_sha256_hash = sha256_hash.hexdigest()
            var_information_sha256hash_write = ("[HASH]: SHA256 Hash for: " + xapk + ".xapk is: " + xapk_sha256_hash + "\n")
            file_txt_update.write(var_information_sha256hash_write)

        sha512_hash = hashlib.sha512()
        with open(xapk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha512_hash.update(byte_block)
            xapk_sha512_hash = sha512_hash.hexdigest()
            var_information_sha512hash_write = ("[HASH]: SHA512 Hash for: " + xapk + ".xapk is: " + xapk_sha512_hash + "\n")
            file_txt_update.write(var_information_sha512hash_write)

########################################################################################################################################
########################################################### UNZIP xAPK Extraction ######################################################
########################################################################################################################################
        
        global var_proc_call_xapk_apk_ripper_dir
        global var_zip_success
        global script_ext_location_check
        global var_apk_ripper_flag
        var_proc_call_xapk_apk_ripper_dir = xapk_extract_directory + "\\"
        var_zip_success = 0
        script_ext_location_check = 0
        var_apk_ripper_flag = 0

        try:
            with ZipFile(xapk_full_path,"r") as var_xapk_unzip:
                var_xapk_unzip.extractall(xapk_extract_directory + "\\")
                var_zip_success = 1
        except:
            if var_forensic_case_bool == 1:
                log_txt_update.write("[WARN]: Error Extracting: " + xapk_full_path + "\n") 
            if arg_verbose_output == 1:
                print("[WARN]: Error Extracting: " + xapk_full_path) 

        if var_zip_success == 1:
            func_hash_all_files()
            func_json_manifest_rip()
        
        directory_search_pattern = (var_proc_call_xapk_apk_ripper_dir+"\\*.apk")
        if var_forensic_case_bool == 1:
            log_txt_update.write("[INFO]: Searching for APKs in: " + directory_search_pattern + "\n")
        if arg_verbose_output == 1:
            print("[INFO]: Searching for APKs in: " + directory_search_pattern)

        for xapk_full_path in glob.glob(directory_search_pattern):
            if xapk_full_path != '':
                var_apk_ripper_flag = 1

        if var_apk_ripper_flag == 1:
            script_ext_location_check = 1
            func_command_call()

########################################################################################################################################
############################################################ Per xAPK Clean-Up #########################################################
########################################################################################################################################     

        if arg_verbose_output == 1:
            print("")
            print("[FIN] ###################################### FIN ######################################")
            print("")

        xapk_move_cleanup_loc = xapk_source_directory + "\\" + xapk_with_extension
        try:
            shutil.move(xapk_full_path, xapk_move_cleanup_loc)
        except:
            log_txt_update.write("[WARN]: Error Moving xAPK: " + xapk_full_path + " to: " + xapk_move_cleanup_loc + "\n")
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
