import os
from dotenv import load_dotenv

# set environment variables
load_dotenv()
VIRUS_TOTAL_KEY = os.getenv("VIRUS_TOTAL_KEY")

from base64 import b64decode
# import face_recognition as fr
import time
import pickle

# def lc(username, image):
# 	try:
# 		face_match = 0
# 		header, encoded = image.split(",", 1)
# 		file_new = ".\\face\\" + str(time.time_ns())
# 		file_exist = ".\\face\\" + str(time.time_ns())
# 	except:
# 		return "Image not clear! Please try again!"
# 	with open(file_new + ".png", "wb") as f:
# 		f.write(b64decode(encoded))

# 	data = pickle.loads(open(".\\face\\data.pickle", "rb").read())
# 	with open(file_exist + ".png", "wb") as f:
# 		f.write(b64decode(data[username]))
	
# 	try:
# 		try:
# 			got_image = fr.load_image_file(file_new + ".png")
# 			existing_image = fr.load_image_file(file_exist + ".png")
# 		except Exception as e:
# 			print(e.__cause__)
# 			return "Data does not exist!"
# 		got_image_facialfeatures = fr.face_encodings(got_image)[0]
# 		existing_image_facialfeatures = fr.face_encodings(existing_image)[0]
# 		results = fr.compare_faces([existing_image_facialfeatures], got_image_facialfeatures)
# 		if(results[0]):
# 			return "Successfully Logged in!"
# 		else:
# 			return "Failed to Log in!"
# 	except Exception as e:
# 		print(e.__cause__)
# 		return "Image not clear! Please try again!"
	
# def rs(username, image):
# 	try:
# 		header, encoded = image.split(",", 1)
# 	except:
# 		return "Image not clear! Please try again!"
# 	try:
# 		try:
# 			data = pickle.loads(open(".\\face\\data.pickle", "rb").read())
# 		except Exception as e:
# 			print(e.__cause__)
# 			data = dict()
# 			with open(".\\face\\data.pickle", "wb") as f:
# 				f.write(pickle.dumps(data))
# 		data = pickle.loads(open(".\\face\\data.pickle", "rb").read())
# 		data[username] = encoded
# 		with open(".\\face\\data.pickle", "wb") as f:
# 			f.write(pickle.dumps(data))
# 	except Exception as e:
# 		print(e.__cause__)
# 		return "Registration failed!"
# 	return "Registration Successful!"



import shelve
import hashlib
import requests
db = shelve.open("database/virus.db",writeback=True)

def generate_hash(filename):
	file_hash= hashlib.md5(open(filename,'rb').read()).hexdigest()
	return file_hash

def check_virus(file_path):
	file_to_check = file_path
	file_hash = generate_hash(file_to_check)

	if file_hash in db['virus']:
		print("Virus Hash found in Database!")
		return True
	else:
		return VT_Request(file_hash)

def VT_Request(hash):
	parameters = {"apikey": VIRUS_TOTAL_KEY, "resource": hash}
	url = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params=parameters)
	json_response = url.json()
	print(json_response)
	response = int(json_response.get("response_code"))

	# DOES THE HASH EXISTS IN VT DATABASE?
	if response == 0:
		print(hash + ": UNKNOWN")

	# DOES THE HASH EXISTS IN VT DATABASE?
	elif response == 1:
		positives = int(json_response.get("positives"))
		if positives >= 3:
			print(hash + ": MALICIOUS")
			print("Appending Virus Hash to Database")
			# db['virus'].append(hash)
			# db.sync()
			return True

		else:
			print(hash + ": NOT MALICIOUS")
			return False

	else:
		print(hash + ": CAN NOT BE SEARCHED")