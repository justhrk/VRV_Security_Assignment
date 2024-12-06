import re
import csv

def FormatLine(line):
    # To get a well formatted line from the log
    regex = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) (.*?)" (\d+) (\d+)(?: "(.*?)")?'

    matches = re.match(regex, line)
    result =[]
    if matches:
        result = [
            matches.group(1),            # IP address
            matches.group(2),            # Date and time
            matches.group(3),            # Method
            matches.group(4),            # Endpoint
            matches.group(5),            # Protocol
            int(matches.group(6)),       # Status code
            int(matches.group(7)),       # Size
            matches.group(8),            # Message
        ]
    return list(result)


def CountRequests(lines):
    # To count the number of requests recieved from a particular ip address
    dct = {}
    for line in lines:
        log = FormatLine(line)
        ip = log[0]
        
        if(ip in dct.keys()):
            dct[ip] += 1
        else:
            dct.update({ip:1})

    result = sorted(dct.items(), key = lambda x : x[1], reverse = True)
    print('IP Address\t\tRequest Count')
    for ip,count in result:
        print(f"{ip}\t\t{count}")

    return result


def FrequentlyAccessedEndpoint(lines):
    # To get the most frequently accessed endpoint
    dct = {}
    for line in lines:
        log = FormatLine(line)

        endpoint = log[3]

        if (endpoint in dct.keys()):
            dct[endpoint] += 1
        else:
            dct.update({endpoint:1})
        
    ep = list(dct.keys())[0]
    count = dct[ep]

    result = []
    for k in dct.keys():
        if( dct[k] > count):
            count = dct[k]
            ep = k
            result.append((ep,count))
    
    print(f"Most Frequently Accessed Endpoint:\n{result[0][0]}  (Accessed {result[0][1]} times)")

    return result

def SuspiciousActivity(lines):
    # To detect any suspicious activity in the logs and flagging ip address with failed login attempts 
    dct = {}
    for line in lines:
        log = FormatLine(line)

        ip = log[0]
        status = log[5]
        message = log[-1]
        failure_message = ['Invalid credentials']

        if (status == 401 or message in failure_message):
            if (ip in dct.keys()):
                dct[ip]+=1
            else:
                dct.update({ip:1})

    result = []

    for k in dct.keys():
        if (dct[k]>10):
            result.append((k,dct[k]))

    print("Suspicious Activity Detected:")
    print("IP Address\t\tFailed Login Attempts")
    for ip,count in result:
        print(f"{ip}\t\t{count}")

    return result



with open ('sample.log','r') as log:
    lines = log.readlines()
    op1 = CountRequests(lines) # Output 1 : Count Requests per IP Address
    print('\n')
    op2 = FrequentlyAccessedEndpoint(lines) # Output 2 : Most Frequently Accessed Endpoint
    print('\n')
    op3 = SuspiciousActivity(lines) # Output 3 : Detect Suspicious Activity


with open ('log_analysis_results.csv', 'w', newline='', encoding='utf-8') as csvfile:
    csvwriter = csv.writer(csvfile)

    csvwriter.writerow(['IP Address','Request Count'])
    for ip,count in op1:
        csvwriter.writerow([ip,count])
    
    csvwriter.writerow([])
    
    csvwriter.writerow(['Endpoint', 'Access Count'])
    for ep,count in op2:
        csvwriter.writerow([ep,count])

    csvwriter.writerow([])

    csvwriter.writerow(['IP Address', 'Failed Login Count']) 
    for ip, count in op3:
        csvwriter.writerow([ip, count])

    print('\nThe Ouput is Stored in "log_analysis_result.csv" .')