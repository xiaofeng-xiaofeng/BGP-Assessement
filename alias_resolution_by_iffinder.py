###############################################################################################
# Process the output of iffinder and get the alias ip set!
# Edited by ligl,2015-04-15
###############################################################################################

import os
import pymongo
import subprocess
#import sys


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





##############################################################################################################
#Do alias resolution by iffinder and remove the tmp or err file.
class  alias_resolution_by_iffinder:
	def __init__(self,ipfile):
		self.ipfile = ipfile
		self.output = 'iffinder_result.out'

	def start(self):
		command = r'./iffinder -c 255 -r 1000 -o iffinder_result  %s'%self.ipfile
		try:
			p = subprocess.Popen(command,shell=True)
			p.wait()

			os.remove('iffinder_result.err')
			return True
		except Exception as e:
			print "fail to do alias resolution by iffinder!"
			print e
			os.remove('iffinder_result.err')
			os.remove('iffinder_result.tmp')
			return False
	



##############################################################################################################
class process_iffinder_output:
	def __init__(self,iffinder_output):
		self.iffinder_output = iffinder_output

	def start(self):
		try:
			hfile=open(self.iffinder_output)
			#halias_pair = open(self.iffinder_output+"_alias_pairs","w")
		except:
			print "Cann't open ",self.iffinder_output
			return False
		try:
			pairs_list = []
			alias_ip_set = set()
			lines = hfile.readlines()
			for line in lines:
				temp = line.split()
				if len(temp)==8:
					if temp[5] == "D":
						#halias_pair.write(temp[0]+"  "+temp[1]+"\n")
						pairs_list.append( set([temp[0],temp[1] ]) )
						alias_ip_set = alias_ip_set |  set([temp[0],temp[1] ])
			print "Get the alias_pairs!"
			hfile.close()
		except Exception as e:
			print "##@@ ",e
			return False		
		#process the pairs_list
		j = 0
		while True :
			ip_num = 0	#the total number of ip in all pairs,it may have same ip in different pairs.
			for i in range(len(pairs_list)):
				ip_num += len(pairs_list[i])
			if len(pairs_list)==1 or ip_num == len(alias_ip_set):
				break
			else:
				try:
					for i in range(len(pairs_list)-1, 0, -1):
						if j != i and len( pairs_list[j] | pairs_list[i] ) < len(pairs_list[j])+len(pairs_list[i]):
							#These two sets have at least one common ip.
							pairs_list[j] = pairs_list[j] | pairs_list[i]
							for k in range(i,len(pairs_list)-1):
								pairs_list[k]=pairs_list[k+1]
							del(pairs_list[len(pairs_list)-1])
							#print "delete a sub_list"
					if j < len(pairs_list)-1:
						j += 1		
					else:
						j=0							
				except Exception as e:
					print "***()() ",e
		#sort the pairs_list by the length of sub_set.
		#sorted(pairs_list, lambda x,y:cmp(len(x),len(y)) ,reverse=True)
		for i in range(len(pairs_list)-1):
			index=i
			for j in range(i+1,len(pairs_list)):
				if len(pairs_list[index]) < len(pairs_list[j]):
					index=j
			temp = pairs_list[i]
			pairs_list[i] = pairs_list[index]
			pairs_list[index] = temp
		print "The total number of alias ips is: ",len(alias_ip_set)
		print "The number of alias set is: ",len(pairs_list)
		temp = db_connect()
		if temp.connect():
			collection = temp.collection
			for i in range(len(pairs_list)):
				for ip in pairs_list[i]:
					collection.update_one({'IP':ip}, {'$set':{'ALIAS_SET_NUM_IFFINDER':i,	       'ALIAS_SET_SIZE_IFFINDER':len(pairs_list[i]) }} )
					#collection.update_one({'IP':ip}, {'$set':{'ALIAS_SET_NUM_IFFINDER':i,	       'ALIAS_SET_SIZE_IFFINDER':len(pairs_list[i]) }} ,True)
			print "Job is done!"
			temp.close()
			return True
		else:
			print "Fail to connect database!"
			return False




##############################################################################################################
def iffinder_alias_resolution(ipfile):
	a = alias_resolution_by_iffinder(ipfile)
	if a.start():
		#process iffinder output and insert into database.
		b = process_iffinder_output(a.output)
		if b.start():
			print "Succeed to insert iffinder output into database!"
			os.remove(a.output)	#remove the iffinder output file.
			return True
		else:
			print "Fail to insert iffinder output into database!"
			os.remove(a.output)	#remove the iffinder output file.
			return False



#iffinder_alias_resolution(sys.argv[1])











