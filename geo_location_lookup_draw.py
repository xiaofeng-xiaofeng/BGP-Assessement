import os
import datetime, numpy
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
import geoip2.database
import pymongo,sys


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



class ip_to_location_lookup:
	#initialize the class,open ipfile and result file,create a reader of "GeoLite2-City.mmdb".
	def __init__(self,ipfile):
		try:
			self.result_list = []
			self.hfile=open(ipfile)
		except:
			print "Cann't open file!"		
		try:
			self.reader=geoip2.database.Reader("GeoLite2-City.mmdb")
		except Exception as e:
			print "Cann't create geoip reader!!"
			print e

	#lookup the location and city name for each ip in the ipfile.
	def start(self):
		try:
			#insert result into database.
			temp = db_connect()
			if temp.connect():
				collection = temp.collection
				while True:
					lines=self.hfile.readlines(1000)
					if lines:
						for line in lines:
							re=self.search_one_ip(line.strip())
							if re:
								# It will add or update 4 attributes if IP is in the database.
								# Otherwise it will not add or update ,because the third parameter of update_one is False.
								collection.update_one( {'IP':line.strip()},{'$set':{'CC':str(re[0]),   		'CITY':str(re[1]),	'LONGTITUDE':str(re[3]),	'LATITUDE':(re[2])} } )
								#It will add or update 4 attributes regardless of whether IP is in database.
								#collection.update_one( {'IP':line.strip()},{'$set':{'CC':str(re[0]),   		'CITY':str(re[1]),	'LONGTITUDE':str(re[3]),	'LATITUDE':(re[2])} } ,True )
					else:
						break
				self.hfile.close()
				self.reader.close()
				temp.close()
			else:
				print "Fail to connect database!"
				return False
			print "Looking up is done!!!"
			return True
		except Exception as e:
			print e
			print "###########"
			self.hfile.close()
			self.reader.close()
			return False

	#Actually search the location and city name for a given IP.
	def search_one_ip(self,ip):
		try:
			response = self.reader.city(ip)
		except Exception as e:
			return False
		if response:
			result=[response.country.name , response.city.name , response.location.latitude , response.location.longitude]
			return result
		else:
			return False


#The argument for this class is loc_list, which is the output of class ip_to_location_lookup.
class statistic_by_location:
	def statistic(self):				
		self.loc_list=[]
		#get longtitude and latitude from database.
		temp = db_connect()
		if temp.connect():
			collection = temp.collection
			for item in collection.find():
				try:	
					if item['LONGTITUDE']  and item['LATITUDE']:
						sub_list = []
						flag= False
						#This item has longtitude and latitude 
						#It should be put into self.loc_list if its city isn't None.
						for i in range(len(self.loc_list)):
							if self.loc_list[i][0] == item['LONGTITUDE'] and self.loc_list[i][1] == item['LATITUDE']:
								self.loc_list[i][2] += 1
								flag = True
								break
						if not flag:
							sub_list.append(item['LONGTITUDE'])
							sub_list.append(item['LATITUDE'])
							sub_list.append(1)
							self.loc_list.append(sub_list)	
				except Exception as e:
					print "######$$$$$*****"
			temp.close()
			print "Statistic is done!!!"
			return self.loc_list
		else:
			print "Fail to connect database!"
			return False



class draw_by_statistic:
	def __init__(self,loc_list,ipfile):
		#The element of loc_list is a list. 
		#The sublist in loc_list has four elements: city   lons   lats   number_of_such_ip
		self.loc_list = loc_list
		self.ipfile = ipfile


	#This function will plot point on the map.
	#The sublist in loc_list just have three elements:longtitude  latitude  number-of-such-IPs
	def draw(self):
		print "Now beginning to save the map ....\n"

		try:
			map_inst = Basemap(projection='hammer',lon_0=90)
			#map_inst=Basemap(projection='ortho',lat_0=35,lon_0=120,resolution='h')

			map_inst.drawcountries(linewidth=0.5,color='#000000')
			map_inst.drawcoastlines(linewidth=0.25,color='#000000')
			map_inst.drawmapboundary(fill_color='#689CD2')

			#It will make the filled color as the background color that  zorder is 0 .
			#zorder is very important parameter.
			map_inst.fillcontinents(color='#ffffff',lake_color='#689CD2',zorder=0)
			#map_inst.fillcontinents(color='#BF9E30',lake_color='#689CD2',zorder=0)

			for sublist in self.loc_list:
				size=sublist[2]/800
				x,y=map_inst(sublist[0],sublist[1]) #change the location to map coordination.
				#print x,"      ",y
				map_inst.scatter(x,y,s=size,marker='o',color='#FF5600')	
			#plt.title('The distribution of open 179 port in china')
			#plt.show() #this function will show a pic window.
			#plt.title("The distribution of %s"%self.ipfile)
			#this function will save a pic in given format. parameter "dpi" decide the resolution of the picture.
			plt.savefig(self.ipfile + "_location.png",dpi=100,format="png")
			return True
		except Exception as e:
			print "###^^^%%%@@@   ",e
			return False




###########################################################################################################

class get_asn_from_cymru:
	def __init__(self,ipfile):
		self.ipfile = ipfile
	#Just calculate the first three part of each IP.
	def transform_ip_to_int(self,ip):
		ip = ip.strip()
		temp = ip.split(".")
		num = int(temp[0])*65536+int(temp[1])*256+int(temp[2])
		#print num
		return num	
	def start(self):
		db_list = []	
		try:
			#print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
			hdbfile = open('cymru_ip2asn_ip2cc_db')
			db_lines = hdbfile.readlines()
			for db_line in db_lines:
				templist = db_line.split("|")
				db_list.append(templist)
			#print "%%%%%%%%%%%%"
			hfile = open(self.ipfile,"r") 
			lines = hfile.readlines()
			#print "&&&&&&&&&&&&&&&&&&"	
		except Exception as e:			
			print "Couldn't open file"
			print e
			return False
		try:	
			if not db_list:
				print "The database list is empty! program will quit!"
				return False
			#insert result into database.
			temp = db_connect()
			if temp.connect():
				collection = temp.collection
				#print "******"
				for line in lines:
					ipnum = self.transform_ip_to_int(line.strip())
					start = 0
					end = len(db_list)
					index = 0		
					while (start < end):
						cursor = (start + end)/2
						if ipnum > int(db_list[cursor][0]) :
							if (end-start)==1:
								index = start
								break
							start = cursor
						else:
							if ipnum == int(db_list[cursor][0]):
								index = cursor
								break
							end = cursor
					if ipnum >= int(db_list[index][0]) :					
						if db_list[index][1].strip() != "NA":
							collection.update_one( {'IP':line.strip()},{'$set':{'ASN':str(db_list[index][1].strip())}})
						else:
							collection.update_one( {'IP':line.strip()},{'$set':{'ASN':None} } )
					else:
						print "Cann't find the ASN for the given IP(%s)"%line.strip()
						collection.update_one( {'IP':line.strip()},{'$set':{'ASN':None} } )
				temp.close()
				hfile.close()
				hdbfile.close()
				print "succeed to do asn lookup"
				return True
			else:
				print "Fail to connect database!"
				hfile.close()
				hdbfile.close()
				return False	
		except Exception as e:
			print e
			#temp.close()
			hfile.close()
			hdbfile.close()
			return False


def start_draw(ipfile):
	print "try to get cc, city, longtitude, latitude"
	starttime=datetime.datetime.now()
	a = ip_to_location_lookup(ipfile)
	if  a.start():
		print "Succeed to get geo_information for ips and insert them into database!"
		b = statistic_by_location()
		loc_list = b.statistic()
		if loc_list:
			c = draw_by_statistic(loc_list,ipfile)
			if c.draw():
				print "Succeed to draw map!"
			else:
				print "Fail to draw map!"
				return False
		else:
			print "loc_list is empty, fail to draw map!"
			return False
	else:
		print "Fail to get geo_infromation and insert them into database!"
	endtime=datetime.datetime.now()
	print "Total time consumed: ",endtime-starttime
	return True



'''
#start_draw(sys.argv[1])

print "try to get asn ..."
c = get_asn_from_cymru(sys.argv[1])
print "start ...."
try:
	c.start()
	print "succeed to do asn lookup!"
except Exception as e:
	print "get asn error:",e
'''


