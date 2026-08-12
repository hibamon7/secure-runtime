print("TEST STARTED")

from dotenv import load_dotenv
import os

print("IMPORTS OK")

load_dotenv()

print("DOTENV LOADED")
print("API KEY:", os.getenv("OPENAI_API_KEY"))

print("TEST FINISHED")