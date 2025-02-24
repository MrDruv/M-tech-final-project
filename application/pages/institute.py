import streamlit as st
import requests
import json
import os
import hashlib
import logging
from dotenv import load_dotenv
from utils.cert_utils import generate_certificate
from utils.streamlit_utils import hide_icons, hide_sidebar, remove_whitespaces
from connection import contract, w3

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Streamlit configuration
st.set_page_config(layout="wide", initial_sidebar_state="collapsed")

remove_whitespaces()

# Load environment variables
load_dotenv()

api_key = os.getenv("PINATA_API_KEY")
api_secret = os.getenv("PINATA_API_SECRET")

def upload_to_pinata(file_path, api_key, api_secret):
    pinata_api_url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": api_key,
        "pinata_secret_api_key": api_secret,
    }

    with open(file_path, "rb") as file:
        files = {"file": (file.name, file)}
        response = requests.post(pinata_api_url, headers=headers, files=files)
        result = json.loads(response.text)

        if "IpfsHash" in result:
            ipfs_hash = result["IpfsHash"]
            logger.info(f"File uploaded to Pinata. IPFS Hash: {ipfs_hash}")
            return ipfs_hash
        else:
            logger.error(f"Error uploading to Pinata: {result.get('error', 'Unknown error')}")
            return None

def fetch_from_pinata(ipfs_hash):
    ipfs_url = f"https://gateway.pinata.cloud/ipfs/{ipfs_hash}"
    response = requests.get(ipfs_url)
    if response.status_code == 200:
        return response.content
    else:
        logger.error("Failed to fetch file from IPFS")
        return None

options = ("Generate Certificate", "View Certificates")
selected = st.selectbox("", options, label_visibility="hidden")

if selected == options[0]:
    form = st.form("Generate-Certificate")
    uid = form.text_input(label="UID")
    candidate_name = form.text_input(label="Name")
    course_name = form.text_input(label="Course Name")
    org_name = form.text_input(label="Org Name")

    submit = form.form_submit_button("Submit")
    if submit:
        pdf_file_path = "certificate.pdf"
        institute_logo_path = "../assets/logo.jpg"
        generate_certificate(pdf_file_path, uid, candidate_name, course_name, org_name, institute_logo_path)

        ipfs_hash = upload_to_pinata(pdf_file_path, api_key, api_secret)
        os.remove(pdf_file_path)
        data_to_hash = f"{uid}{candidate_name}{course_name}{org_name}".encode('utf-8')
        certificate_id = hashlib.sha256(data_to_hash).hexdigest()

        try:
            tx_hash = contract.functions.generateCertificate(certificate_id, uid, candidate_name, course_name, org_name, ipfs_hash).transact({'from': w3.eth.accounts[0]})
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            st.success(f"Certificate successfully generated with Certificate ID: {certificate_id}")
        except Exception as e:
            logger.error("Could not transact with/call contract function, is contract deployed correctly and chain synced?", exc_info=True)
            st.error("An error occurred while generating the certificate. Please try again.")

else:
    form = st.form("View-Certificate")
    certificate_id = form.text_input("Enter the Certificate ID")
    submit = form.form_submit_button("Submit")
    if submit:
        try:
            certificate_data = contract.functions.getCertificate(certificate_id).call()
            if certificate_data:
                ipfs_hash = certificate_data[4]
                file_content = fetch_from_pinata(ipfs_hash)
                if file_content:
                    st.download_button(label="Download Certificate", data=file_content, file_name="certificate.pdf")
                else:
                    st.error("Error fetching certificate from IPFS")
            else:
                st.error("Invalid Certificate ID!")
        except Exception as e:
            logger.error("Could not fetch the certificate data from the smart contract", exc_info=True)
            st.error("An error occurred while fetching the certificate. Please try again.")
