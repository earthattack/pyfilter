# -*- coding: utf-8 -*-
import time, os, subprocess, sys, re, getopt, datetime, shutil

## GLOBAL VARS
LAST_LINES = 500
AUTH_LAST_LINES = 100
SECONDS_CYCLE = 10
MAX_SIGNUP = 5
MAX_POST = 5
SOURCE_DIRECTORY = "/home/antibot"

APPS_ADMITED = ['sharetronix']

## GLOBAL LOCALS



BLOCKEDS_IN_EXE = []

## EXCEPTIONS

r=open("/home/exceptions.filter","r")
r.readlines()
EXCEPTIONS_IPS = []
for line in r:
  line = line.rstrip('\n')
	EXCEPTIONS_IPS.append(line)

def check_ufw():
	c = os.popen("which ufw").read()

	if not c:
		os.popen("apt-get install ufw").read()
		print "Instalando ufw..."
		sleep(3)
		os.popen("ufw default allow").read() # default allow
		os.popen("ufw enable").read() # enable firewall

	c = os.popen("ufw status").read()

def check_apache_dump():

	os.popen("a2enmod dump_io && service apache2 restart")

	dnoui = os.popen("egrep 'DumpIOInput[[:space:]](On|Off)' /etc/apache2/apache2.conf").read()
	if not len(dnoui) == 0:
		r = os.popen("egrep 'DumpIOInput[[:space:]](On|Off)' /etc/apache2/apache2.conf | awk '{if($2 != \"On\" || $2 != \"Off\") print \"No\"; else print $2}'").read()
		if r is "Off":
			try:
				f = open("/etc/apache2/apache2.conf","a")
				dt = datetime.datetime.now()

				## copying file
				shutil.copyfile("/etc/apache2/apache2.conf",SOURCE_DIRECTORY+"/cp/")

				dt.strftime("%Y-%m-%d %H:%M")
				f.write("\n### ADDED AT "+str(dt)+" BY BOT: dump_io CONF ###\n<IfModule mod_dumpio>\nDumpIOInput On\nDumpIOLogLevel debug\n</IfModule>")
				f.close()
			except IOError:
				print("Ha habido un error al tratar de escribir en el archivo ")
				exit()
			else:
				exit()
		elif r is "No"
	else:

def block_ip(ip):
	
	# read if blocked 

	r=open("/home/blocked.list","r")
	r = r.readlines()
	ips = []
	for line in r:
		line = line.rstrip('\n')
		ips.append(line)
	print ip

	if BLOCKEDS_IN_EXE.count(ip) > 0:
		print "La ip "+str(ip)+" ya esta bloqueada"

	else:
		print "bloqueando..."
		r = open("/home/blocked.list","rw+")
		r.seek(0,2)
		r.write(str(ip)+"\n")
		os.popen("ufw insert 1 deny from "+str(ip)+" to any port 80").read()
		print "bloqueado"
		BLOCKEDS_IN_EXE.append(ip)
		r.close()

def email_alert(txt,subject):

	import smtplib
	from email.mime.multipart import MIMEMultipart
	from email.mime.text import MIMEText

	originm ="xxxx@gmail.com"
	destinationm = ["xxxxx@gmail.com","xxxxx@gmail.com"]

	msg = MIMEMultipart("alternative")

	msg['Subject'] = subject
	msg['From'] = "XXXX <xxx@gmail.com>"
	msg['To'] = "XXX <xxx@gmail.com>, XXXX <xxx@gmail.com>"

	msge = MIMEText(txt,"html")

	msg.attach(msge)

	objectsmtp = smtplib.SMTP_SSL("smtp.gmail.com",465)
	rc = objectsmtp.login("xxxxx","xxxx")
	#if rc[0] != 235:
	#	print "Ha habido un error al loguearse con el servidor SMTP"
	#	exit("Saliendo de ejecucion")
	rc = objectsmtp.sendmail(originm,destinationm,msg.as_string())
	#if rc[0] != 221:
	#	print "Ha habido un error al enviar el email"
	#	exit("Saliento de ejecucion")
	objectsmtp.quit()

def auth_analysis():

	auth_read = os.popen("tail -n "+str(AUTH_LAST_LINES)+" /var/log/auth.log | grep 'failed'").read()

	#auth_read = str(auth_read).split("\n")

	if len(auth_read) > 0:
		print "Se encontró algo en auth.log"
		email_alert("Se adjunta la siguiente información sobre el intento:\n"+str(auth_read),"Intento sospechoso de acceso vía SSH (puerto 22)")

	else:
		print "No se encontró nada en auth.log"


def detect():
	print "Inicializando..."
	i = 0;

	#Infinite cycle
	while True:
		i = i+1

		print "\n"+ str(i)+" comprobacion:"
		actual_read = os.popen("tail -n "+ str(LAST_LINES) + " "+ str(ACTUAL_ACCESS_LOG)).read()

		SUSPICIOUS_L1 = []
		SUSPICIOUS_L2 = []
		SUSPICIOUS_L3 = []

		# splitting

		petitions_actuals = str(actual_read).split("\n")
		petitions_actuals_desglosed = []
		ip_list = []

		for line in petitions_actuals:
			if len(line) > 0:
				nwline = str(line).split(";")
				if not ip_list.count(nwline[0]):
					ip_list.append(nwline[0])
				petitions_actuals_desglosed.append(nwline)

		# ip by ip except exceptions
		for ip in ip_list:
			if EXCEPTIONS_IPS.count(ip) == 1 or BLOCKEDS_IN_EXE.count(ip) >= 1:
				continue
			else:
				print "## Examinando la ip "+str(ip)+" ##"
				SIGNUP_COUNTER = 0
				POSTFORM_COUNTER = 0
				print ""
				index = 0
				## stats ##
				for actualu in petitions_actuals_desglosed:
					index += 1
					if actualu[0] == ip:
						if re.search("signup",actualu[2]):
							SIGNUP_COUNTER +=1
						elif re.search("postform-submit",actualu[2]):
							POSTFORM_COUNTER +=1
					# when the loop has > of numberforpetitions for actions final
					if index == LAST_LINES:
							if SIGNUP_COUNTER > MAX_SIGNUP:
								block_ip(ip)
								subject = "IP bloqueada"
								txt = "La ip <b>"+str(ip)+"</b> ha sido bloqueada por registrarse más de "+str(MAX_SIGNUP)+" veces en un tiempo limitado."
								email_alert(txt,subject)
							elif POSTFORM_COUNTER > MAX_POST:
								block_ip(ip)
								subject = "IP bloqueada"
								txt = "La ip "+str(ip)+" ha sido bloqueada por `postear más de "+str(MAX_POST)+" veces en un tiempo limitado."
								email_alert(txt,subject)
							else:
								print "#Nada encontrado#\n\n"

		auth_analysis()
		print "Esperando para el siguiente bucle"
		time.sleep(10)

if len(sys.argv) == 1:
	autodetect()

else:
	opt,extr = getopt.getopt(sys.argv[1:])
	for op,arg in opt:
		if op in ['-f','--access']:
			ACTUAL_ACCESS_LOG = arg
		elif op in ['-l','--limit']:
			LAST_LINES = arg
		elif op in ['-t','--time']:
			SECONDS_CYCLE = arg
		elif op in ['-ms',"--maxsignup"]:
			MAX_SIGNUP = arg
		elif op in ['-ml','--maxlogin']:
			MAX_LOGIN = arg
		elif op in ['-app','--application']:
			ACTUAL_APP = arg
		elif op in ['-e','--email']:
			EMAIL_NOT =arg
		elif op in ['-eu','--emailuser']:
			EMAIL_USER = arg
		elif op in ['-pu','--passuser']:
			EMAIL_PASS = arg
		elif op in ['-dbu','--databaseuser']:
			DB_USER = arg
		elif op in ['-dbp','--databasepass']
			DB_PASS = arg

	## tries open file log
	if os.path.isfile(ACTUAL_ACCESS_LOG):
		try:
		f = open(str(ACTUAL_ACCESS_LOG),"r")
		except IOError:
			print "Imposible abrir el archivo de Log: access.log en la ruta "+str(ACTUAL_ACCESS_LOG)+", especifique correctamente el archivo"
			exit()
		else:
			print "Ha ocurrido un error al intentar abrir el archivo "+str(ACTUAL_ACCESS_LOG)
			exit()
	else:
		print "El archivo de access.log introducido no existe"

	## OTHERS
	if not str(LAST_LINES).isdigit():
		print "La variable --limit ha de ser un número"
		exit()
	elif not str(MAX_SIGNUP).isdigit():
		print "La variable --maxsignup ha de ser un número"
		exit()
	elif not str(MAX_LOGIN).isdigit():
		print "La variable --maxlogin ha de ser un número"
		exit()
	elif not str(SECONDS_CYCLE).isdigit():
		print "La variable --time ha de ser un número"
		exit()
	if not ACTUAL_APP in APPS_ADMITED:
		print "La aplicación indicada no está soportada aún"
		exit()

	check_apache_dump()