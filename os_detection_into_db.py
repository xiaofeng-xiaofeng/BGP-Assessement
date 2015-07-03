import subprocess
import threading
#import os
import sys
import datetime
import time


import pymongo
#####################################################################################################
#Sometimes the output may don't have the device type so the length os sub_list is just 3.
#STEP should be set as 1 when there will be fastest scan speed.
#I need to add option parameter.
#Edit by ligl,2015-04-10
#####################################################################################################



#this class is responsible for connecting with mongodb
class db_connect:
	def __init__(self,dbname='bgp_router_db'):
		self.dbname = dbname

	def connect(self):
		try:
			self.client=pymongo.MongoClient('127.0.0.1',27017)
			self.db=self.client[ self.dbname ]
			self.collection=self.db['bgp_router_collection']
			return True

		except Exception as e:
			print "Cann't connect database!"
			print e
			return False

	def close(self):
		#close the connection,because the interval between inserting into database is very long.
		self.client.close()




#################################################################################################
class os_detect:
	def __init__(self,ipfile,max_thread):
		self.ipfile=ipfile
		self.max_thread = max_thread
		self.mutex=threading.Lock()
		self.sem=threading.BoundedSemaphore(self.max_thread)

	def detect(self,ip):
		#command="nmap -p 179 -O  %s"%ip
		command="nmap -p 179 -O  %s"%ip
		try:
			print "start a new child thread!"
			hdata=subprocess.Popen(command,stdout=subprocess.PIPE,shell=True)
		except Exception as e:
			print "@@@@@@@@"
			print e
			self.sem.release()	#Must release the semaphore,otherwise it will reduce the number of running thread!
			return False
		#print hdata.stdout.read()
		try:
			if self.mutex.acquire():
				self.hresult.write(hdata.stdout.read())
				self.mutex.release()
				self.sem.release()
				return True
		except Exception as e:
			print "######"
			print e
			self.sem.release()
			return False


	def start(self):
		try:
			self.hipfile=open(self.ipfile,"r")
		except:
			print "Cann't open %s" % self.ipfile
			return False		
		try:
			self.output = self.ipfile+"_os_detection_output"  #In order to process os_detection_output.

			self.hresult=open(self.ipfile+"_os_detection_output","w")
		except:
			print "Cann't create file: nmap-output"
			return False

		starttime=datetime.datetime.now()
		try:
			while True:
				lines=self.hipfile.readlines()
				if lines:
					iplist=[]
					for line in lines:
						iplist.append(line.strip())
					print "*******************************************"
					print "length of iplist is:",len(iplist)
					print "*******************************************"
					try:
						for i in range(len(iplist)):
							self.sem.acquire()
							aa=" ".join(iplist[i:i+1])
							print aa
							p=threading.Thread(target= self.detect , args=(aa ,))	
							p.start()

							#p.setDaemon(True) #This function will kill child thread when the main thread quit!
							#p.join()
					except Exception as e:
						print "Fail to detect OS fingerprint! "
						print e
				else:
					break
				#time.sleep(2)
		finally:
			#time.sleep(1000)
			#The thread-number includes the main thread. So the number is 1 means only main thread left!
			while len(threading.enumerate()) > 1 :
				#print "There are %d thread in running!"%len(threading.enumerate())
				time.sleep(10)

			self.hipfile.close()
			self.hresult.close()
			endtime=datetime.datetime.now()
			print "Os detection consumed: ",endtime-starttime





#################################################################################################
#Process the os detection output.
class process_os_detect_output:

	def __init__(self,outputfile):
		self.outputfile = outputfile

	def extract(self):
		try:
			hfile=open(self.outputfile)			
		except Exception as e:
			print "@#@#@#@# ",e
			return False
		total_list = []	#element is a sub_list.
		sub_list   = ['','',''] #element is: ip  port_status  device_type  os_detection.
		try:
			while True:
				lines=hfile.readlines(1000)
				if lines:
					#print "starting to read ...."
					for line in lines:
						temp=line.split()
						if len(temp)>1:
							try:
								#print "result number is: ",len(total_list)
								if temp[0]=="Nmap" and temp[1]=="scan":
									#start a new sub_list 
									if sub_list[2] :
										total_list.append(sub_list)	
										#print "a new sub_list is added!"
									sub_list   = ['','','']
									#get ip address from the line!
									if line.find("(") != -1:
										ip = temp[-1][1:-1].strip()
									else:
										ip = temp[-1].strip()			
									sub_list[0]=ip
								elif temp[0].strip()=="Device" and temp[1].strip()=="type:":
									#device type
									device_type = line.split(":")[1].strip()
									sub_list[1]=device_type							
								elif temp[0]=="Running":
									#os type
									os_detection = line.split(":")[1].strip()
									sub_list[2]=os_detection							
								elif temp[0]=="Aggressive" and temp[1]=="OS":
									#detailed os type
									os_detection = line.split(":")[1].split(",")[0]
									sub_list[2]=os_detection							
								elif temp[0]=="Too" and temp[1]=="many":
									#no matchable os type
									#os_detection = ""
									sub_list   = ['','','']
							except Exception as e:
								print "Fail to process the output of os  fingerprint!"
								print e
								return False							
				else:
					#finish processing output file!
					break
			#the last sub_list
			if sub_list[2] :
				total_list.append(sub_list)	
				#print "$$$$ tatal_list is: ",total_list
			hfile.close()
			return total_list
		except Exception as e:
			print e
			print "Something was wrong!"
			hfile.close()
			return False

	def start(self):
		print "Begin to process os detection output...."
		total_list = self.extract()
		#insert result into database.
		if total_list:
			#connect to mongodb
			temp = db_connect()
			if temp.connect():
				collection = temp.collection
				#Insert OS_TYPE and device_type into database!
				for sub_list in total_list:
					try:
						collection.update_one({'IP':sub_list[0]}, {'$set':{'DEVICE_TYPE':sub_list[1],	'OS_TYPE':sub_list[2] }})
					except Exception as e:
						print "Fail to insert item: %s"%sub_list[0]
				temp.close()
				return True
			else:
				print "Fail to connect database!"
				return False
		else:
			print "No item in OS_TYPE list"
			return False



#################################################################################################
def get_os_fingerprint(ipfile,max_thread=20):
	#detect the os fingerprint
	a=os_detect(ipfile,max_thread)
	a.start()	#no return value for this function.
	#process the os_detection_output and insert the result into database.
	b=process_os_detect_output(a.output)
	if b.start():
		print "Succeed to get os fingerprint and store into database!"
		return True
	else:
		print "Fail to get os fingerprint and store into database!"
		return False


#get_os_fingerprint(sys.argv[1],20)




	
