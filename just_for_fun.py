import re
import time
import requests
from bs4 import BeautifulSoup as bs
from lxml import html
from selenium import webdriver

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException

delay_normal = 3
delay_small = 1
jello_wrapper = 'JelloWrapper'

cve_url = "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180010"

eula_url = "https://portal.msrc.microsoft.com/en-US/eula"

eula_checkbox_xpath_class = "ng-pristine ng-invalid ng-invalid-required ng-touched"
eula_checkbox_xpath = '//*[@id="JelloWrapper"]/div[3]/div[2]/div/ui-view/form/div[1]/label/input'
selector = '#JelloWrapper > div.alley > div.securityeula > div > ui-view > form > div.checkbox > label > input'

headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}

title_xpath = '//h2[@id="JelloWrapper"]//text()'

chromeOptions = webdriver.ChromeOptions()
prefs = {'profile.managed_default_content_settings.images': 2}
chromeOptions.add_experimental_option("prefs", prefs)
chromeOptions.add_argument('--headless')
driver = webdriver.Chrome(chrome_options=chromeOptions)


def clear(message):
    message = message.replace("\n", " ").replace("\r", " ").lstrip().rstrip()
    re.sub('\s+', ' ', message).strip()
    return message

try:
    print('get EULA page')
    driver.get(eula_url)
    element_present = EC.presence_of_element_located((By.LINK_TEXT, "terms of service"))
    WebDriverWait(driver, delay_normal).until(element_present)
    time.sleep(delay_normal)
    print('click checkbox')
    driver.execute_script('document.getElementsByTagName("input")[3].click()')
    print('click accept button')
    driver.execute_script('document.getElementsByTagName("input")[4].click()')
    print('ok')
except TimeoutException as te:
    print("Get an timeout exception: {}".format(te))

try:
    print('get vulnerability page')
    driver.get(cve_url)
    element_present = EC.presence_of_element_located((By.LINK_TEXT, "Dashboard"))
    WebDriverWait(driver, delay_normal).until(element_present)
    time.sleep(delay_small)
    r = clear(str(driver.execute_script("return document.getElementsByClassName('ng-binding')[0].innerText")))
    print('title: \n', format(r))
    r = clear(str(driver.execute_script("return document.getElementsByClassName('ng-binding')[26].innerText")))
    print('published: \n', format(r))
    r = clear(str(driver.execute_script("return document.getElementsByClassName('ng-binding')[161].innerText")))
    print('faq: \n', format(r))
    r = clear(str(driver.execute_script("return document.getElementsByClassName('ng-binding')[165].innerText")))
    print('acknowledgements: \n', format(r))
    r = clear(str(driver.execute_script("return document.getElementsByClassName('ng-binding')[167].innerText")))
    print('disclaimer: \n', format(r))

except Exception as ex:
    print("Get an exception: {}".format(ex))



print('complete')


