import requests
from tqdm import tqdm
import time

url = "https://github.com/singlecore06483/sc_framework"

response = requests.get(url)

if response.status_code == 200:
    print("Starting Database...")
    for i in tqdm(range(85), desc="Loading"):
        time.sleep(0.1)
    print("\nDatabase Loaded Successfully!")
else:
    print("Failed to retrieve data from the URL.")