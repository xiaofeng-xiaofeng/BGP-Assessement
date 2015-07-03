import os
import subprocess


#The host with 1Mbps bandwidth will scan 5,000,000 ips in one hour.This parameter specifies the ip number you want to scan one time. 
#You had better not to modify the value of "IP_NUM_PER_SCAN",otherwise it may trigger alarm.
IP_NUM_PER_SCAN = 300000 
CURRENT_DIR = os.path.abspath( os.path.dirname(__file__) )
os.chdir(CURRENT_DIR)

#This class will format the ipfile and split big file by the value of "IP_NUM_PER_SCAN" and bandwidth.
class process_file:
	#format the ipfile.
	def __init__(self,ipfile,bandwidth='1M'):
		#open the IP file and the result file.
		try:
			self.ipfile = ipfile
			self.bandwidth=bandwidth   #The function which invokes this class is responsible for setting the bandwidth of scanning.
			self.standardised_file = ipfile+"_standardised"
			hfile = open(self.ipfile,"r")
			hiptable = open(self.ipfile+"_standardised","w")
		except Exception as e:
			print "cann't open file."
			print e
			return False
		try:
			lines=hfile.readlines()
			for line in lines:
				temp=line.split("/")
				if (len(temp) == 1) or (int(temp[1]) >= 24) :
					hiptable.write(line.strip() + "\n")
				elif len(temp) == 2:
					try:
						#change the ip block into a ip list.
						a = temp[0].split(".")	#temp[0] is a ip, while temp[1] is the length of mask.
						start_num = (int(a[0])*65536+int(a[1])*256+int(a[2]))*256 + int(a[3]) / ( 2**(32-int(temp[1])) )
						total_number = 2**(32 - int(temp[1]) -8)
					except Exception as e:
						print "something was wrong when processes the ip block."
						print e
					for i in range(total_number):
						#change the int into ip and write ip into file.
						try:
							ip_split=["","","","0"]
							b=start_num+i
							for i in range(3):
								ip_split[2-i] = str(b%256)
								b /= 256
							ip = ".".join(ip_split)
						except Exception as e:
							print "fail to transform ip block."
							print e
						hiptable.write( ip + "/24" + "\n")
						#hiptable.write( socket.inet_ntoa(struct.pack('I',socket.htonl(start_num + i))) + "\n")
				else:
					print "Incorrect format: ",line
			hfile.close()
			hiptable.close()
			print "standardise the ipfile"
			#return True
		except Exception as e:
			print "***",e
			hfile.close()
			hiptable.close()
			#return False	

	#Split the big ipfile in order to scan the sub_ip_file apart with given interval.
	#The return value is the number of subfiles.
	def split_file(self):
		try:
			hipfile = open(self.standardised_file)
		except Exception as e:
			print "Cann't open standardised file!",e
			return 0	
		try:
			total_number = 0
			lines = hipfile.readlines()
			for line in lines:
				total_number += self.count_number(line)
			#The number of sub_ip_file is determined by the self.bandwidth and scanning speed.
			sub_file_num = total_number/(IP_NUM_PER_SCAN * int(self.bandwidth.split("M")[0]) ) + 1
			#print "%d  subfiles"%sub_file_num		
			index_of_ipfile = -1
			start = 0
			end = 0
			#print "length of lines is:",len(lines)
			for i in range(sub_file_num):
				#find the index where the number of ips in the subfile is big than the average number of each subfile.
				sub_num = 0
				while sub_num < total_number/sub_file_num:
					if end+1 < len(lines):
						end += 1
					else:
						end += 1
						break
					sub_num += self.count_number( lines[end] )
				hsubfile = open(self.standardised_file+"_sub_"+str(i), "w")
				for line in lines[start:end+1]:
					hsubfile.write(line.strip() + "\n")
				hsubfile.close()
				#print "%d:   start:%d  , end:%d"%(i,start,end)
				start = end+1	#The end line will be written into subfile.
			try:
				#remove the standardised_file,parameter "self.standardised_file" will be useless.
				os.remove(self.standardised_file)
			except:
				print "Cann't remove ",self.standardised_file
			print "%s has been splitted into %d subfiles."%(self.standardised_file,sub_file_num)
			return sub_file_num
			
		except Exception as e:
			print "Some errors happen when scan ipfile!"
			print e
			return 0

	#Count the IP number in the CIDR-style line.
	def count_number(self,line):
		try:
			temp=line.split("/")
			if (len(temp) == 1) or (int(temp[1])==32) :
				return 1
			elif len(temp) == 2:
				#count the ip number of this block.
				number = 2**(32-int(temp[1]))
				return number
			else:
				print "Incorrect format: ",line
				return 0
		except Exception as e:
			print "***",e
			return 0


class scan_collect:
	#Use zmap to scan the given port in subfile. 
	#The output will be in standard format,like "port+"_"+subfile".
	def __init__(self,subfile,port,timestamp=False,bandwidth='1M',interface='eth0',probe_times=1):
		self.port = str(port)
		self.bandwidth = bandwidth
		self.interface = interface
		self.probe_times = probe_times
		self.subfile = str(subfile.strip())
		self.timestamp = timestamp
		#The crontab will not find zmap without the path of zmap. This  command will not be executed.
		#The supported parameters are destination_port, interface, bandwidth, probe_times.
		#The name of whitelist_file and output_file is fixed.
		command = "/usr/sbin/zmap -B %s -i %s -p %s -P %s  -w %s  -o %s  -q  "%( self.bandwidth,  self.interface,  self.port, self.probe_times,   self.subfile,   self.port+"_"+self.subfile)
		#command = "zmap -B %s -i %s -p %s -P %s  -w %s  -o %s  -q  "%( self.bandwidth,  self.interface,  self.port, self.probe_times,   self.subfile,   self.port+"_"+self.subfile)
		try:
			#os.chdir(CURRENT_DIR)
			#If the parameter "shell" is set "True",the command will be executed by shell!
			p = subprocess.Popen(command,shell=True)
			p.wait() #wait the subprocess  by command to finish.
		except Exception as e:
			print "!@#  ",e

	#Collect the output of subfiles for given port and filter it.
	def collect_output(self):
		try:
			#os.chdir(CURRENT_DIR)
			#Get the name of ipfile from the name of subfile.
			end   = self.subfile.find("_standardised")
			ipfile = self.subfile[ :end ]
			#if timestamp is false,it means last scanning succeed ,so a new timestamp is needed.
			if  not self.timestamp :
				#Name the final port scan output file with a new timestamp.
				houtput = open(self.port+"_"+ipfile+"_"+TIMESTAMP,"a")	
			elif ipfile.find(self.timestamp) == -1:
				#Name the final port scan output file with a old timestamp.
				houtput = open(self.port+"_"+ipfile+"_"+self.timestamp,"a")		
			else:
				#The ipfile already has a timestamp in the second step.
				houtput = open(self.port+"_"+ipfile,"a") 
		except Exception as e:
			print "%%%^^^^  ",e
			return False
		try:
			#os.chdir(CURRENT_DIR)
			hsuboutput = open( self.port+"_"+self.subfile )			
		except Exception as e:
			print "!!!!!",e
			return False
		try:
			while True:
				lines = hsuboutput.readlines(1000)
				if lines:
					for line in lines:
						if len(line.split(".")) == 4:
							houtput.write(line.strip()+"\n")
				else:
					break
			hsuboutput.close()
			houtput.close()
			try:
				#remove the output of subfile and subfile.
				os.remove(self.subfile)
				os.remove(str(self.port)+"_"+self.subfile)
			except:
				print "Cann't delete  ",str(self.port)+"_"+self.subfile	
			return True
		except:
			print "Cann't collect the output of ",self.subfile
			return False



