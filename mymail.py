import imaplib, email ,hashlib ,simplejson, urllib, urllib2,json

#log in and select the inbox
mail = imaplib.IMAP4_SSL('imap.gmail.com')
mail.login('teju.chinnu604@gmail.com', 'T3j@$w1ni')
mail.select('inbox')
global  md5_returned
#get uids of all messages
result, data = mail.uid('search', None, 'ALL') 
uids = data[0].split()

#read the lastest message
result, data = mail.uid('fetch', uids[-1], '(RFC822)')
m = email.message_from_string(data[0][1])

if m.get_content_maintype() == 'multipart': #multipart messages only
    for part in m.walk():
        #find the attachment part
        if part.get_content_maintype() == 'multipart': continue
        if part.get('Content-Disposition') is None: continue

        #save the attachment in the program directory
        filename = part.get_filename()
        fp = open(filename, 'rb+')
	#hash_val=hashlib.md5(fp.read()).hexdigest()
	with open(filename) as file_to_check:
	    # read contents of the file
	    data = file_to_check.read()    
	    # pipe contents of the file through
	    md5_returned = hashlib.md5(data).hexdigest()

        fp.write(part.get_payload(decode=True))
        fp.close()
	file_to_check.close()
        #print '%s saved!' % filename
	#print 'MD5 : %s' % md5_returned
	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": md5_returned, "apikey": "0aab19f66ecb807b778a7fd7e1f0f85afe8aea6e2ed64c58607acddbdb552ca7"}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	rep = response.read()
	#print '\n '
	response_dict = json.loads(rep)
	Av_scan=response_dict.get("positives",{})
	#print json
	#pos=getattr(json, "positives")
	#pos=json.get('positives')
	#print pos
	
