from os import listdir
from copy import deepcopy
from html import unescape
import email
'''
- The primary goal of this project is to identify the sources of these emails if they are from the same person.
-I believe that this one individual is sending out these emails with a fake email address. 
I also have their real email address and want to compare the two to see if this is the same person sending these emails.
'''
class EMLReader:
    def __init__(self, directory) -> None:
        self.emails_directory = directory
        self.emails_file_names = listdir(self.emails_directory)
        self.lookup = {"headers": list,
                       "email_address": str,
                       "domain_address": str,
                       "common_name": str,
                       "ip_address": str,
                       "dkim": [],
                       "timezone": str,
                       "subject": str,
                       "charset": str,
                       "dkim_pass": False,
                       "spf_pass": False,
                       "dmarc_pass": False,
                       "mx": str
                       }
    
    def data_eml(self, eml):
        return email.message_from_string(eml).items()

    def parse_eml(self):
        eml_files = []
        meta = []
        
        for email in self.emails_file_names:
            with open(f'{self.emails_directory}/{email}') as eml_file:
                data = eml_file.read()
                eml_files.append(self.data_eml(data))
        
        if len(eml_files) > 0:
            for eml_file in eml_files:
                let = deepcopy(self.lookup)
                for key, value in eml_file:
                    if key == 'Authentication-Results':
                        splited_values = value.split()
                        for item in splited_values:
                            if item == 'dkim=pass':
                                let["dkim_pass"] = True
                            if item == 'spf=pass':
                                let["spf_pass"] = True
                            if item == 'dmarc=pass':
                                let["dmarc_pass"] = True
                                 
                        let["mx"] = splited_values[0]
                        #let["ip_address"] = splited_values[15]
                    
                    if key == 'Received-SPF':
                        splited_values = value.split()
                        let["ip_address"] = splited_values[-1].split("=")[-1].replace(";", "")
                        
                    if key == 'From':
                        let["email_address"] = value.split()[-1].replace('<', '').replace('>', '')
                        let["common_name"] = value.split()[0]
                        let["domain_address"] = let["email_address"].split('@')[-1]
                        
                    if key == 'Date':
                        let["timezone"] = value  
                    
                    if key == 'DKIM-Signature':
                        let["dkim"].append(value)
                    
                    if key == 'Content-Type':
                        let["charset"] = value.split()[-1].split('=')[-1]
                        
                    if key == 'Subject':
                        let["subject"] = unescape(value)
                        
                        meta.append(let)
        return meta           
                
                
eml = EMLReader('./emails')
emls = eml.parse_eml()

print(emls[0]["mx"])
print(emls[1]["mx"])
print(emls[2]["mx"])
print(emls[3]["mx"])
print(emls[4]["mx"])

