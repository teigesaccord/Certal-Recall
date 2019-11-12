
import socket
from socket import timeout, error
import ssl, boto3
import re,sys,os,datetime
import json
from botocore.vendored import requests

def ssl_expiry_date(domainname):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=domainname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)
    conn.connect((domainname, 443))
    ssl_info = conn.getpeercert()
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt).date()


def ssl_valid_time_remaining(domainname):
    """Number of days left."""
    expires = ssl_expiry_date(domainname)
    return expires - datetime.datetime.utcnow().date()


def sns_sender(ssl_list):
    # sslStat = '\n'.join(ssl_list)
    # snsSub = 'Here is the list of ssl expiration dates. '
    slack_emergency = []
    for item in ssl_list:
        if 'will be expiring very soon:' in item:
            slack_emergency.append(item)
    
    # response = client.publish(
    # TargetArn="PUT_ARN_HERE_FOR_EMAILS,
    # Message= sslStat,
    # Subject= snsSub
    # )
    
    if not slack_emergency:
        slack_emergency.append("Looks like no SSL is in peril")
        post_to_slack(slack_emergency)
    else:
        slack_emergency.append("<!channel>")
        post_to_slack(slack_emergency)
    
    
    
def post_to_slack(message=None):

    webhook_url = "SLACK_WEB_HOOK_GOES_HERE"
    slack_data = {'text': '\n'.join(message)}
    print('\n'.join(message))
    
    
    response = requests.post(
        webhook_url, data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text)
            )
        

#####Main Section
# client = boto3.client('sns')
def lambda_handler(event, context):
    no_alert = True
    ssl_list= []
    HOST_LIST = []
    table = boto3.resource('dynamodb').Table('SSL-Expiry_Checker') #Looks for dynamoDB table. Can use ENVIRONMENTAL VARIABLES TOO
    response = table.scan()

    for i in response['Items']: 
        json_str = json.dumps(i)
        resp_dict = json.loads(json_str)
        HOST_LIST.append(resp_dict.get('domain_name'))

    for dName in HOST_LIST:
        # print(dName)
        try:
            expDate = ssl_valid_time_remaining(dName.strip())
            print expDate
            (a, b) = str(expDate).split(',')
            (c, d) = a.split(' ')
            if int(c)<30:
                ssl_list.append(dName + ' will be expiring very soon: ' + str(c) +' days. ')
            else:
                ssl_list.append(dName + ' expires in ' + str(c) +' days. ')

        except (error, timeout, dName) as err:
            print (" Oops I guess there was a timeout error with"+dName)
    sns_sender(ssl_list)