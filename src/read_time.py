'''
Created on Jun 9, 2014

@author: elingyu
'''

#! /usr/bin/python

import optparse

from datetime import datetime

def parse_args():
    usage = """usage: %prog [options]
This is the wireshark file handler.
Run it like this:

    python read_time.py -d "C:\simon\Company\SBG\Test_result\R14B\Logs\SBG-SCT-4401.2\" -a "access.txt" -c "core.txt" -r "res.txt"  
    
"""
    parser = optparse.OptionParser(usage)
    parser.add_option("-d", "--directory", dest="directory", type="string", help="access network", default="c:")
    parser.add_option("-a", "--access", dest="access", type="string", help="access network", default="access.txt")
    parser.add_option("-c", "--core", dest="core", type="string", help="core network", default="core.txt")
    parser.add_option("-r", "--result", dest="result", type="string", help="result file", default="res.txt")

    (options, _) = parser.parse_args()

    print "The directory is %s" % (options.directory)

    print "The access network file is %s" %(options.access)
    
    print "The core network file is %s" %(options.core)
    
    print "The result will be put in the file %s" %(options.result)

    return options.directory, options.access, options.core, options.result


def cal_reg(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Request: REGISTER" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Request: REGISTER" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["REGISTER Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close()
    

def cal_inv(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Request: INVITE" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Request: INVITE" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["INVITE Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close()
    

def cal_rin(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Status: 180 Ringing" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Status: 180 Ringing" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["180 Ringing Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close()


def cal_ok(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Status: 200 OK" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Status: 200 OK" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["200 OK Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close()
    

def cal_ack(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Request: ACK" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Request: ACK" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["ACK Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close()


def cal_bye(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Request: BYE" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Request: BYE" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["BYE Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close() 


def cal_sub(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Request: SUBSCRIBE" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Request: SUBSCRIBE" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["SUBSCRIBE Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close() 


def cal_pub(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Request: PUBLISH" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Request: PUBLISH" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["PUBLISH Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close() 


def cal_mes(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Request: MESSAGE" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Request: MESSAGE" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["MESSAGE Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close() 
    

def cal_not(directory, access, core, result):
    access_file = open(directory + "//" + access, 'r')
    access_time = []
    for line in access_file:
        if "Request: NOTIFY" in line:
            access_time.append(line.split()[1])
    if len(access_time) == 0:
        return
    print access_time
    access_file.close()

    core_file = open(directory + "//" + core, 'r')
    core_time = []
    for line in core_file:
        if "Request: NOTIFY" in line:
            core_time.append(line.split()[1])
    print core_time
    core_file.close()

    access_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in access_time]
    core_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(access_time, core_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["NOTIFY Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close() 
    

def cal_dia(directory, access, core, result):
    core_file = open(directory + "//" + core, 'r')
    core_time_1 = []
    for line in core_file:
        if "cmd=AARequest" in line:
            core_time_1.append(line.split()[1])
    if len(core_time_1) == 0:
        return
    print core_time_1
    core_file.close()
    
    core_file = open(directory + "//" + core, 'r')
    core_time_2 = []
    for line in core_file:
        if "cmd=AAAnswer" in line:
            core_time_2.append(line.split()[1])
    print core_time_2
    core_file.close()

    core_time_1 = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time_1]
    core_time_2 = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_time_2]
    diff = [abs((a - c).total_seconds()) for a,c in zip(core_time_1, core_time_2)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["DIAMETER Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close() 
    

def cal_h248(directory, access, core, result):
    core_file = open(directory + "//" + core, 'r')
    core_add_req_time = []
    for line in core_file:
        if "Add=" in line and "Request" in line:
            core_add_req_time.append(line.split()[1])
    if len(core_add_req_time) == 0:
        return
    print core_add_req_time
    core_file.close()
    
    core_file = open(directory + "//" + core, 'r')
    core_add_rep_time = []
    for line in core_file:
        if "Reply" in line and "Add=" in line:
            core_add_rep_time.append(line.split()[1])
    print core_add_rep_time
    core_file.close()

    core_add_req_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_add_req_time]
    core_add_rep_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_add_rep_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(core_add_req_time, core_add_rep_time)]
    print diff
    
    ave = sum(diff) / len(diff)
    print ave
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in diff + ["H.248 Add and Reply Average delay: " + str(ave) + " secs" + "\n"])
    result_file.close() 
    

    core_file = open(directory + "//" + core, 'r')
    core_Modify_req_time = []
    for line in core_file:
        if "Modify=" in line and "Request" in line:
            core_Modify_req_time.append(line.split()[1])
    if len(core_Modify_req_time) == 0:
        return
    print core_Modify_req_time
    core_file.close()
    
    core_file = open(directory + "//" + core, 'r')
    core_Modify_rep_time = []
    for line in core_file:
        if "Reply" in line and "Modify=" in line:
            core_Modify_rep_time.append(line.split()[1])
    print core_Modify_rep_time
    core_file.close()

    core_Modify_req_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_Modify_req_time]
    core_Modify_rep_time = [datetime.strptime(r, '%H:%M:%S.%f') for r in core_Modify_rep_time]
    diff = [abs((a - c).total_seconds()) for a,c in zip(core_Modify_req_time, core_Modify_rep_time)]
    print diff
    
    req_180_time=[]
    req_200_time=[]
    for i in range (len(diff)):
        if i % 2 == 0 :
            req_180_time.append(diff[i])
        else :
            req_200_time.append(diff[i])

    
    req_180_time_ave = sum(req_180_time) / len(req_180_time)
    
    req_200_time_ave = sum(req_200_time) / len(req_200_time)
    
    print req_180_time
    
    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in req_180_time + ["H.248 Modify and Reply Average delay for 180 Ringing message: " + str(req_180_time_ave) + " secs" + "\n"])
    result_file.close() 
    
    print req_200_time

    result_file = open(directory + "//" + result, 'a')
    result_file.writelines(str(i)+"\n" for i in req_200_time + ["H.248 Modify and Reply Average delay for 200 OK message: " + str(req_200_time_ave) + " secs" + "\n"])
    result_file.close() 
    
    
if __name__ == '__main__':
    parameters = parse_args()
    
    cal_reg(*parameters)
    cal_inv(*parameters)
    cal_rin(*parameters)
    cal_ok(*parameters)
    cal_ack(*parameters)
    cal_bye(*parameters)
    cal_sub(*parameters)
    cal_pub(*parameters)
    cal_mes(*parameters)
    cal_not(*parameters)
    cal_dia(*parameters)
    cal_h248(*parameters)
    
    print "Done!"


