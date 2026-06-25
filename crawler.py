import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse 
from datetime import datetime

start_url = "https://example.com/"

response = requests.get(start_url)
soup = BeautifulSoup(response.content,"html.parser")

hidden_normal_length = len(response.text) 
visible_normal_length = len(soup.get_text())

print (f"status code is {response.status_code} and normal visible lenght is : {visible_normal_length} and normal inspact length is {hidden_normal_length}")
print("\n")


# ---------- cookies Inputs ----------
cookies = {}
for cookie in response.cookies:
    cookies[cookie.name] = cookie.value


print("All cookies are: ")
print(cookies)


# ---------- Search Inputs ----------
print("\n[ Search Inputs ]")
search_box = [] 

for inp in soup.find_all("input"):

    if inp.get("type") == "search": 
         search_box.append(inp.get("name"))   
       

print(f"search box type : {search_box}")


payload_set = {'and true --', "' or 1=1--", "'union select null--"}

db_errors = [
    "sql syntax",
    "mysql",
    "mariadb",
    "sqlite",
    "postgresql",
    "odbc",
    "unclosed quotation mark",
    "warning:"
]

file_name = datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"

safe = ""

with open(f"Web scanner Reports/{file_name}", "a") as file:  
     file.write("This is a scanner report of analysied webapplication responses on sql injections:\n\nSearch box testing ...........\n\n")


#------------------search box report----------------------------------------
final_verdict = "Final verdict: Search box not exists on page "

if (len(search_box) >0): 
    for bug in payload_set:
        payload = bug

        for search in search_box:     
            params = {f'{search}':f'{payload}'}
            response = (requests.get(start_url, params= params))
            soup2 = BeautifulSoup(response.content, "html.parser")
        
            print("\n")
            response_status_code = f" Status code vulnerability exists status code {response.status_code}." if (response.status_code) != 200 else f" No Status code vulnerability, status code is {response.status_code}."
            response_time = f"Page load time based sql vulnerability exists, load time is {response.elapsed.total_seconds()}." if response.elapsed.total_seconds()> 7 else f"No Page load time based vulnerability, load time is {response.elapsed.total_seconds()}."
            response_hidden_length = f"Page response length changed,length is {len(response.text)}. Blind sql injection posibility" if (((len(response.text)) != hidden_normal_length) and response.status_code == 200) else f"Page response length not changed, length is {len(response.text)}. No blind sql vulnerability on page on scanning." 
            response_visible_length =  f"Page visible length changed,length is {len(soup2.get_text())}. Something misbehaving on queries injection. May be some information leak happened" if (((len(soup2.get_text())) != visible_normal_length) and response.status_code == 200) else f"Page visible length not changed, length is {len(soup2.get_text())}. No information leak on scanning." 
    
            for error in db_errors:
                if error in response.text:
                    response_error = "Detailed Error based sql vulnerability exists."
                    break 

                else:
                    response_error ="No detailed Error based sql vulnerability not exists."
    
            print (response_status_code,"\n", response_time,"\n", response_visible_length,"\n", response_hidden_length,"\n", response_error)
    
            if "No" not in (response_status_code or response_time or response_hidden_length or response_visible_length or response_error): 
                safe = "Search box is vulnerable for SQL injection"
    
            with open(f"Web scanner Reports/{file_name}", "a") as file:
                file.write(f'We checked search fields (name "{search}") with "{payload}"')
                file.write("\n")
                file.write(f"{response_status_code}")
                file.write("\n")
                file.write(f"{response_time}")
                file.write("\n")
                file.write(f"{response_hidden_length}")
                file.write("\n")
                file.write(f"{response_visible_length}")
                file.write("\n")
                file.write(f"{response_error}")
                file.write("\n\n\n")

    if len(safe) < 2:  
        safe = "Searchbox has no SQL vulnerability\n\n\n"

    with open(f"Web scanner Reports/{file_name}", "a") as file:
        file.write(f"{safe}") 
        file.write("\n")
        file.close()

    print("\n",safe)

    if "no" in safe:
        final_verdict = "Final verdict: search box is not vulnerable "
    else:
        final_verdict = "Final verdict: search box is vulnerable "

else:
    safe = "\nSearch box not exist."
    print(safe)
    with open(f"Web scanner Reports/{file_name}", "a") as file:
        file.write(f"{safe}") 
        file.write("\n")


#------------------cookies report----------------------------------------
with open(f"Web scanner Reports/{file_name}", "a") as file:
    file.write("Cookies testing ...........\n\n")

if (len(cookies) >0):
    safe = "Cookies has no SQL vulnerability\n\n\n"  

    for bug in payload_set:
        payload = bug

        for name, value in cookies.items():
            modified_value = value + payload
            params = { name: modified_value }

            response = (requests.get(start_url, cookies= params))
            soup2 = BeautifulSoup(response.content, "html.parser")

            print("\n")
            response_status_code = f" Status code vulnerability exists status code {response.status_code}." if (response.status_code) != 200 else f" No Status code vulnerability, status code is {response.status_code}."
            response_time = f"Page load time based sql vulnerability exists, load time is {response.elapsed.total_seconds()}." if response.elapsed.total_seconds()> 7 else f"No Page load time based vulnerability, load time is {response.elapsed.total_seconds()}."
            response_hidden_length = f"Page response length changed,length is {len(response.text)}. Blind sql injection posibility" if (((len(response.text)) != hidden_normal_length) and response.status_code == 200) else f"Page response length not changed, length is {len(response.text)}. No blind sql vulnerability on page on scanning." 
            response_visible_length =  f"Page visible length changed,length is {len(soup2.get_text())}. Something misbehaving on queries injection. May be some information leak happened" if (((len(soup2.get_text())) != visible_normal_length) and response.status_code == 200) else f"Page visible length not changed, length is {len(soup2.get_text())}. No information leak on scanning." 
    

            for error in db_errors:
                if error in response.text:
                    response_error = "Detailed Error based sql vulnerability exists."
                    break 

                else:
                    response_error ="No detailed Error based sql vulnerability not exists."
        
            print (response_status_code,"\n", response_time,"\n", response_visible_length,"\n", response_hidden_length,"\n", response_error)

            if "No" not in (response_status_code or response_time or response_hidden_length or response_visible_length or response_error): 
                safe = "Cookies are vulnerable for SQL injection"

            with open(f"Web scanner Reports/{file_name}", "a") as file:
                file.write(f'We checked cookies (name "{name, value}")  with "{payload}"')
                file.write("\n")
                file.write(f"{response_status_code}")
                file.write("\n")
                file.write(f"{response_time}")
                file.write("\n")
                file.write(f"{response_hidden_length}")
                file.write("\n")
                file.write(f"{response_visible_length}")
                file.write("\n")
                file.write(f"{response_error}")
                file.write("\n\n\n")

    print("\n",safe)

    if "no" in safe:
        final_verdict = final_verdict + "| cookies are not vulnerable."
    else:
        final_verdict = final_verdict + "| cookies are vulnerable."

    print("\n",final_verdict)

    with open(f"Web scanner Reports/{file_name}", "a") as file:
        file.write(f"{safe}") 
        file.write("\n")
        file.write("\n")
        file.write(f"{final_verdict}")
        file.close()
else:
    final_verdict = final_verdict + "| cookies not exist on page."
    safe = "cookies not exist\n\n\n"
    print("\n",safe)
    print("\n",final_verdict)
    with open(f"Web scanner Reports/{file_name}", "a") as file:
        file.write(f"{safe}") 
        file.write("\n")
        file.write(f"{final_verdict}")
        file.close()

