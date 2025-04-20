# unofficial NIST NVD mirror

# Not endorsed by NIST and I don't work for NIST or any American company and I am not a US citizen.

Given the recent event about MITRE nearly lost fundings to maintain CVE, and that my job heavily builds upon NVD/CVE data, I think I should create a mirror of NVD's database.

I add indentation to JSON data, other than that I don't make any intentional change, but there is no gurantee that no mistake have been made.

**Don't use in prod!** I might setup some kind of automation to keep this repository up to date but if you need NVD data for your job you should get NVD data yourself

## How to download/update NVD data yourself

1. Install [uv](https://docs.astral.sh/uv/)
2. Get an API key from [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) and put it in APIKEY.txt. (create the text file yourself)
3. uv run script.py