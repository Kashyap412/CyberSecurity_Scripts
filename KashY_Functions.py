# KashY Required Functions

import requests, os, re, sys, datetime, iocextract, time, tldextract

def clear():
	os.system('cls')

def Banner(a):
	print("\n"+"#"*49+"\n#\t\t\t\t\t\t#")
	print("#\tWelcome to KashY "+a+"\t#\t\n#\t\t\t\t\t\t#")
	print("#"*49+"\n\n")

def End_Banner():
	print("\n"+"#"*49+"\n#\t\t\t\t\t\t#")
	print("#\t   Dump Collection Done !! \t\t#\n#\t\t\t\t\t\t#")
	print("#"*49+"\n\n")


def is_valid_ipv4(ip):
    pattern = re.compile(r"""^(?:(?:[3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}|0x0*[0-9a-f]{1,2}|0+[1-3]?[0-7]{0,2})(?:\.(?:[3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}|0x0*[0-9a-f]{1,2}|0+[1-3]?[0-7]{0,2})){0,3}|0x0*[0-9a-f]{1,8}|0+[0-3]?[0-7]{0,10}|429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8})$""", re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None

def is_valid_ipv6(ip):
    pattern = re.compile(r"""^\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}(?: (?<=::)|  (?<!:)|  (?<=:) (?<!::) :)|(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)(?: \.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*$""", re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None


def ioc_write2md5hashfile(source,data,category,ioc_score):
	now=datetime.datetime.utcnow()
	Dump_Date = str(now.year)+"-"+str(now.month)+"-"+str(now.day)
	file = 'kashy-collect-'+Dump_Date+'-'+source+'.md5.hash.csv'
	with open(file,"a") as w_file:
		w_file.write('KashY-'+str(source)+',Malicious-Hash,'+str(data)+','+str(category)+','+str(ioc_score)+"\n")

def ioc_write2sha1hashfile(source,data,category,ioc_score):
	now=datetime.datetime.utcnow()
	Dump_Date = str(now.year)+"-"+str(now.month)+"-"+str(now.day)
	file = 'kashy-collect-'+Dump_Date+'-'+source+'.sha1.hash.csv'
	with open(file,"a") as w_file:
		w_file.write('KashY-'+str(source)+',Malicious-Hash,'+str(data)+','+str(category)+','+str(ioc_score)+"\n")

def ioc_write2sha256hashfile(source,data,category,ioc_score):
	now=datetime.datetime.utcnow()
	Dump_Date = str(now.year)+"-"+str(now.month)+"-"+str(now.day)
	file = 'kashy-collect-'+Dump_Date+'-'+source+'.sha256.hash.csv'
	with open(file,"a") as w_file:
		w_file.write('KashY-'+str(source)+',Malicious-Hash,'+str(data)+','+str(category)+','+str(ioc_score)+"\n")

def ioc_write2sha512hashfile(source,data,category,ioc_score):
	now=datetime.datetime.utcnow()
	Dump_Date = str(now.year)+"-"+str(now.month)+"-"+str(now.day)
	file = 'kashy-collect-'+Dump_Date+'-'+source+'.sha512.hash.csv'
	with open(file,"a") as w_file:
		w_file.write('KashY-'+str(source)+',Malicious-Hash,'+str(data)+','+str(category)+','+str(ioc_score)+"\n")

def ioc_write2ipv4file(source,data,category,ioc_score):
	now=datetime.datetime.utcnow()
	Dump_Date = str(now.year)+"-"+str(now.month)+"-"+str(now.day)
	file = 'kashy-collect-'+Dump_Date+'-'+source+'.ipv4.ip.csv'
	with open(file,"a") as w_file:
		w_file.write('KashY-'+str(source)+',Malicious-IP,'+str(data)+','+str(category)+','+str(ioc_score)+"\n")

def ioc_write2ipv6file(source,data,category,ioc_score):
	now=datetime.datetime.utcnow()
	Dump_Date = str(now.year)+"-"+str(now.month)+"-"+str(now.day)
	file = 'kashy-collect-'+Dump_Date+'-'+source+'.ipv6.ip.csv'
	with open(file,"a") as w_file:
		w_file.write('KashY-'+str(source)+',Malicious-IP,'+str(data)+','+str(category)+','+str(ioc_score)+"\n")

def ioc_write2domainfile(source,data,category,ioc_score):
	now=datetime.datetime.utcnow()
	Dump_Date = str(now.year)+"-"+str(now.month)+"-"+str(now.day)
	file = 'kashy-collect-'+Dump_Date+'-'+source+'.domain.domain.csv'
	with open(file,"a") as w_file:
		w_file.write('KashY-'+str(source)+',Malicious-Domain,'+str(data)+','+str(category)+','+str(ioc_score)+"\n")

def ioc_write2file(source,check_type,data,category,ioc_score):
	now=datetime.datetime.utcnow()
	Dump_Date = str(now.year)+"-"+str(now.month)+"-"+str(now.day)
	file = 'kashy-collect-'+Dump_Date+'-'+source+'dummy.others.csv'
	with open(file,"a") as w_file:
		w_file.write('KashY-'+str(source)+','+check_type+','+str(data)+','+str(category)+','+str(ioc_score)+"\n")


def extract_md5(content):
  hashes = []
  for i in iocextract.extract_md5_hashes(content):
    hashes.append(i)
  hashes = list(set(hashes))
  return hashes

def extract_ip4(content):
  ips = []
  for i in iocextract.extract_ipv4s(content):
    ips.append(i)
  ips = list(set(ips))
  return ips

def extract_ip6(content):
  ips = []
  for i in iocextract.extract_ipv6s(content):
    ips.append(i)
  ips = list(set(ips))
  return ips

def extract_URL(content):
  URLS = []
  for i in iocextract.extract_urls(content):
    URLS.append(i)
  URLS = list(set(URLS))
  return URLS

def extract_Domain(content):
    domain = []
    for i in iocextract.extract_urls(content):
        data = i.split("/")
        try:
            ip = data[2].split(":")
            domain.append(ip[0])
        except: pass
    return domain


def download_hash(source,url,category,ioc_score):
	result = []
	r = requests.get(url)
	result.extend(extract_md5(r.text))
	for item in result:
		ioc_write2md5hashfile(source,item,category,ioc_score)

def download_ipv4(source,url,category,ioc_score):
	result = []
	r = requests.get(url)
	result.extend(extract_ip4(r.text))
	for item in result:
		ioc_write2ipv4file(source,item,category,ioc_score)

def download_ipv6(source,url,category,ioc_score):
	result = []
	r = requests.get(url)
	result.extend(extract_ip6(r.text))
	for item in result:
		ioc_write2ipv6file(source,item,category,ioc_score)

def download_domain(source,url,category,ioc_score):
	result = []
	r = requests.get(url)
	result.extend(extract_Domain(r.text))
	for item in result:
		ioc_write2domainfile(source,item,category,ioc_score)

def extract_Domain_from_url(url,delim,index,rchar):
	r = requests.get(url)
	time.sleep(2)
	domainlist=[]
	for i in r.text.split('\n'):
		if i.find('!') == -1 and i.find('#') == -1 and i.find('[') == -1:
			if rchar != "":
				i=i.replace("^","")
			t=i.split(delim)[index]
			if t != '':
				a = tldextract.extract(t)
				if a.subdomain != "" and a.suffix !="" and a.domain !="":
					domainlist.append(a.subdomain + "." + a.domain + "." + a.suffix)
				elif(a.suffix !="" and a.domain !=""):
					domainlist.append(a.domain + "." + a.suffix)
				elif(a.domain !=""):
					domainlist.append(a.domain)

	return domainlist

def download_domain_from_url(source,category,ioc_score,url,delim,index,rchar):
	try:
		result = []
		result.extend(extract_Domain_from_url(url,delim,index,rchar))
		for item in result:
			ioc_write2domainfile(source,item,category,ioc_score)
	except: pass


def dump_otx(api_key):
	if len(api_key.strip())<1:
		print("No api key specified.")
		sys.exit(1)
	now=datetime.datetime.utcnow()
	yesterday=datetime.datetime(now.year,now.month,now.day-1,now.hour,now.minute,now.second,now.microsecond).isoformat()
		
	resp=requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50000&modified_since="+yesterday.strip(),headers={"X-OTX-API-KEY":api_key})
	resp = resp.json()
	try:
		for i in range(0,len(resp['results']),1):
			for j in range(0,len(resp['results'][i]['indicators']),1):
			
				check_type = resp['results'][i]['indicators'][j]['type']
				ioc_value = resp['results'][i]['indicators'][j]['indicator']
				source = 'otx'
        
				if check_type == 'CVE':
					category = 'cve'
					ioc_score = 17
					ioc_write2file(source,check_type,ioc_value,category,ioc_score)
				
				if check_type == 'FileHash-MD5':
					category = 'category'
					ioc_score = 17
					ioc_write2md5hashfile(source,check_type,ioc_value,category,ioc_score)
				
				if check_type == 'FileHash-SHA1':
					category = 'category'
					ioc_score = 17
					ioc_write2sha1hashfile(source,check_type,ioc_value,category,ioc_score)
				
				if check_type == 'FileHash-SHA256':
					category = 'category'
					ioc_score = 17
					ioc_write2sha256hashfile(source,check_type,ioc_value,category,ioc_score)
				
				if check_type == 'hostname' :

					if 'www' in ioc_value:
						ioc_value=ioc_value.split('www.')[1]
						category = 'category'
						ioc_score = 17
						ioc_write2domainfile(source,check_type,ioc_value,category,ioc_score)
						
					else:
						category = 'category'
						ioc_score = 17
						ioc_write2domainfile(source,check_type,ioc_value,category,ioc_score)

				if check_type == 'domain' :
					category = 'category'
					ioc_score = 17
					ioc_write2domainfile(source,check_type,ioc_value,category,ioc_score)
				
				if check_type == 'URL' :
					
					ioc_value = ioc_value.split('/')[2]

					if is_valid_ipv4(ioc_value):
						category = 'category'
						ioc_score = 17
						ioc_write2ipv4file(source,check_type,ioc_value,category,ioc_score)
						
					if is_valid_ipv6(ioc_value):
						category = 'category'
						ioc_score = 17
						ioc_write2ipv6file(source,check_type,ioc_value,category,ioc_score)
					if not is_valid_ipv4(ioc_value):
						category = 'category'
						ioc_score = 17
						ioc_write2domainfile(source,check_type,ioc_value,category,ioc_score)

				if check_type == 'email' :
					category = 'category'
					ioc_score = 17
					ioc_write2file(source,check_type,ioc_value)
				if check_type == 'IPv4' :
					category = 'category'
					ioc_score = 17
					ioc_write2ipv4file(source,check_type,ioc_value,category,ioc_score)
				
				if check_type == 'IPv6' :
					category = 'category'
					ioc_score = 17
					ioc_write2ipv6file(source,check_type,ioc_value,category,ioc_score)

	except:
		pass

def dump_virusshare_single():
	for i in range(0,10):
		result = []
		i = str(i)
		url = "https://virusshare.com/hashfiles/VirusShare_0000"+i+".md5"
		r = requests.get(url)
		result.extend(extract_md5(r.text))
		for item in result:
			source = 'virusshare'
			category = 'category'
			ioc_score = 17
			ioc_write2md5hashfile(source,item,category,ioc_score)
			
def dump_virusshare_double():
	for i in range(10,99):
		result = []
		i = str(i)
		url = "https://virusshare.com/hashfiles/VirusShare_000"+i+".md5"
		r = requests.get(url)
		result.extend(extract_md5(r.text))
		for item in result:
			source = 'virusshare'
			category = 'category'
			ioc_score = 17
			ioc_write2md5hashfile(source,item,category,ioc_score)

def dump_virusshare_triple():
	try:
		for i in range(100,999):
			result = []
			i = str(i)
			url = "https://virusshare.com/hashfiles/VirusShare_00"+i+".md5"
			r = requests.get(url)
			result.extend(extract_md5(r.text))
			for item in result:
				source = 'virusshare'
				category = 'category'
				ioc_score = 17
				ioc_write2md5hashfile(source,item,category,ioc_score)

	except: pass

def dump_virusshare_unpacked():
	result = []
	url = "https://virusshare.com/hashfiles/unpacked_hashes.md5"
	r = requests.get(url)
	result.extend(extract_md5(r.text))
	for item in result:
		source = 'virusshare'
		category = 'category'
		ioc_score = 17
		ioc_write2md5hashfile(source,item,category,ioc_score)

def dump_virusshare():
	dump_virusshare_single()
	dump_virusshare_double()
	dump_virusshare_triple()
	dump_virusshare_unpacked()

def dump_threatcrowd():
	result = []
	url = "https://www.threatcrowd.org/feeds/hashes.txt"
	r = requests.get(url)
	result.extend(extract_md5(r.text))
	for item in result:
		source = 'threatcrowd'
		category = 'category'
		ioc_score = 17
		ioc_write2md5hashfile(source,item,category,ioc_score)

def dump_vxvault():
	result = []
	for i in range(0, 15000, 40):
		i = str(i)
		url = "http://vxvault.net/ViriList.php?s="+i+"&m=40"
		r = requests.get(url)
		result.extend(extract_md5(r.text))
		for item in result:
			source = 'vxvault'
			category = 'category'
			ioc_score = 17
			ioc_write2md5hashfile(source,item,category,ioc_score)

def dump_malshare(api_key,category,ioc_score):
	result = []
	url = "http://malshare.com/api.php?api_key=" + api_key + "&action=getlistraw"
	user_agent = {'User-Agent': 'MalShare API Tool v/0.1 beta'}
	r = requests.get(url, headers=user_agent)
	result.extend(extract_md5(r.text))
	for item in result:
		source = 'malshare'
		ioc_write2md5hashfile(source,item,category,ioc_score)


def dump_iocs_once():
	
	print("Bulk IOC Dump Starts")

	dump_virusshare() 
	dump_vxvault()

	download_hash(source='threatcrowd',url='https://www.threatcrowd.org/feeds/hashes.txt',category='category',ioc_score=17)
	download_hash(source='cloud_xvirus',url='http://cloud.xvirus.net/database/viruslist.txt',category='category',ioc_score=17)
	download_hash(source='vetted-cyberthreatcoalition',url='https://blocklist.cyberthreatcoalition.org/vetted/hash.txt',category='category',ioc_score=17)
	
	download_ipv4(source='blocklist',url='https://lists.blocklist.de/lists/all.txt',category='category',ioc_score=17)
	download_ipv4(source='cinsscore',url='http://cinsscore.com/list/ci-badguys.txt',category='category',ioc_score=17)
	download_ipv4(source='vetted-cyberthreatcoalition',url='https://blocklist.cyberthreatcoalition.org/vetted/ip.txt',category='category',ioc_score=17)
	download_ipv6(source='blocklist',url='https://lists.blocklist.de/lists/all.txt',category='category',ioc_score=17)
	download_ipv6(source='cinsscore',url='http://cinsscore.com/list/ci-badguys.txt',category='category',ioc_score=17)
	download_ipv6(source='vetted-cyberthreatcoalition',url='https://blocklist.cyberthreatcoalition.org/vetted/ip.txt',category='category',ioc_score=17)
	
	download_domain(source='vetted-cyberthreatcoalition',url='https://blocklist.cyberthreatcoalition.org/vetted/domain.txt',category='category',ioc_score=17)
	download_domain(source='vetted',url='https://blocklist.cyberthreatcoalition.org/vetted/url.txt',category='category',ioc_score=17)

	print("Bulk IOC Dump Collection Done !!")
	

def daily_ioc_dump():
	
	print("Daily IOC Dump Starts")
	
	dump_otx(api_key='53c74f6312ebc9089b48998e7cb519813978f21144323e9cc6c5259dad9cb64b1712')
	
	dump_malshare(api_key = '4c1f9ca3bb0668152475b4495ac0e766abcykhe6711f5b75ba3b24cb2a98493f7bc',category='category',ioc_score=17)
	download_hash(source='tweet',url='http://www.tweettioc.com/feed/daily/md5',category='category',ioc_score=17)
	
	download_ipv4(source='rescure.fruxlabs',url='https://rescure.fruxlabs.com/rescure_blacklist.txt',category='category',ioc_score=17)
	download_ipv4(source='dshield',url='https://www.dshield.org/ipsascii.html',category='category',ioc_score=17)
	download_ipv4(source='emergingthreats',url='http://rules.emergingthreats.net/blockrules/compromised-ips.txt',category='category',ioc_score=17)
	download_ipv4(source='alienvault',url='http://reputation.alienvault.com/reputation.data',category='category',ioc_score=17)
	download_ipv4(source='torproject',url='https://check.torproject.org/exit-addresses',category='category',ioc_score=17)
	download_ipv4(source='firehol',url='https://iplists.firehol.org/files/firehol_level1.netset',category='category',ioc_score=17)
	
	download_domain(source='openphish',url='https://openphish.com/feed.txt',category='phishing',ioc_score=17)

	download_domain_from_url(source='carl',category='category',ioc_score=17,url='http://www.carl.net/spam/access.txt',delim='REJECT',index=0,rchar="")
	download_domain_from_url(source='abuse',category='category',ioc_score=17,url='https://urlhaus.abuse.ch/downloads/hostfile/',delim='	',index=1,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/AdguardDNS.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/BillStearns.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/Easylist.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/Easyprivacy.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/Kowabit.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/Prigent-Ads.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/Prigent-Malware.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/Prigent-Phishing.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/Shalla-mal.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='firebog',category='category',ioc_score=17,url='https://v.firebog.net/hosts/static/w3kbl.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='joewein',category='category',ioc_score=17,url='https://joewein.net/dl/bl/dom-bl-base.txt',delim=',',index=0,rchar="")
	download_domain_from_url(source='joewein',category='category',ioc_score=17,url='https://joewein.net/dl/bl/dom-bl.txt',delim=',',index=0,rchar="")

	print("Daily IOC Dump Collection Done !!")
	
