# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
#
# size  : is in KB for each chunk in the loop
# loops : how many chunks to download
# mss   : the mss of the traffic 
#######
# for testing one big TCP flow 

from trex.astf.api import *

# we can send either Python bytes type as below:
http_req = b'GET /3384 HTTP/1.1\r\nHost: 22.0.0.3\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)\r\nAccept: */*\r\nAccept-Language: en-us\r\nAccept-Encoding: gzip, deflate, compress\r\n\r\n'
# or we can send Python string containing ascii chars, as below:


class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, size, loop, mss):

        http_response = 'HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/6.0\r\nContent-Type: text/html\r\nContent-Length: 32000\r\n\r\n<html><pre>'+('*'*size*1024)+'</pre></html>'

        bsize = len(http_response)

        # Configure TCP client program
        prog_c = ASTFProgram()
        prog_c.send(http_req)
        prog_c.recv(bsize*loop)

        # Configure TCP server program
        prog_s = ASTFProgram()
        prog_s.recv(len(http_req))
        #prog_s.set_var("var1",10) # not used var, just for the example
        prog_s.set_var("var2",loop) # set var 0 to 10 
        prog_s.set_label("a:")
        prog_s.send(http_response)
        prog_s.jmp_nz("var2","a:") # dec var "var2". in case it is *not* zero jump a: 


        # Showcase TCP tuning
        info = ASTFGlobalInfo()
        if mss:
          info.tcp.mss = mss
        info.tcp.initwnd = 20 # start big
        info.tcp.no_delay = 1   # to get fast feedback for acks
        info.tcp.rxbufsize = 1024*1024  # 1MB window 
        info.tcp.txbufsize = 1024*1024  
        #info.tcp.do_rfc1323 =0


        # Define IP generators
        ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        temp_c = ASTFTCPClientTemplate(program=prog_c, ip_gen=ip_gen, cps=1, limit=1)
        temp_s = ASTFTCPServerTemplate(program=prog_s)  # using default association
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)

        profile = ASTFProfile(default_ip_gen=ip_gen, 
                              templates=template,                              
                              default_c_glob_info=info,
                              default_s_glob_info=info)

        return profile

    def get_profile(self, size=1, loop=10, mss=0, **kwargs):
        return self.create_profile(size, loop, mss)


def register():
    return Prof1()
