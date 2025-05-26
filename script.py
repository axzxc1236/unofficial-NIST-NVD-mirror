#! /usr/bin/env -S uv run --script
# "This product uses the NVD API but is not endorsed or certified by the NVD."
# Original Python script is licensed under MIT license, created by axzxc1236
import asyncio
import niquests
import orjson
import re
import subprocess
import traceback
from datetime import datetime, timezone, timedelta
from pathlib import Path
from time import sleep

CVE_pattern = re.compile(r"CVE-(?P<year>\d+)-(?P<number>\d+)")

with open("APIKEY.txt") as apikey_txt:
    APIKEY = apikey_txt.readline()
    if len(APIKEY) != 36:
        raise Exception("API key is a UUID (with 36 characters) but APIKEY.txt's content is not 36 characters long, please register yourself an API key at https://nvd.nist.gov/developers/request-an-api-key it's automated process and you will get one in no time.")

class APIWorker():
    API_path: str
    query_parameters: dict
    until_timestamp: int
    finished = False
    critical_failure = False
    
    def __init__(self,
                 worker_name: str,
                 API_path: str,
                 data_key: str,
                 since_parameter_name: str,
                 until_parameter_name: str,
                 since: datetime|None=None
                 ):
        self.worker_name = worker_name
        self.API_path = API_path
        self.data_key = data_key
        self.query_parameters = {}
        until = datetime.now(tz=timezone.utc).replace(microsecond=0)
        if since:
            self.query_parameters[since_parameter_name] = since.isoformat()
            if (until - since).days >= 120:
                # NVD's API only allows time range of maximum 120 days, this program limits the time range to less than 120 days to be safe
                # which can be a problem if you only run this program like twice every year (In my use case there is no way to hit this limit)
                # Bootstrapping is not affected because this program doesn't set a time range if you are bootstrapping
                until = since + timedelta(days = 119, seconds=86000) # I choose 119 days and 86000 seconds to make sure leap second doesn't mess with the program
            self.query_parameters[until_parameter_name] = until.isoformat()
        self.until_timestamp = int(until.timestamp())
    
    async def run(self):
        index = 0
        sleep_time = 0
        try:
            async with niquests.AsyncSession(multiplexed=True) as s:
                while True:
                    print(f"[{datetime.now()}][{self.worker_name}] Making API request...")
                    self.query_parameters["startIndex"] = index
                    try:
                        request_start = datetime.now()
                        response = await s.get(f"https://services.nvd.nist.gov/{self.API_path}", timeout=20, headers={"apiKey": APIKEY}, params=self.query_parameters)
                        await s.gather(response)
                        seconds_took = (datetime.now( ) -request_start).total_seconds()
                        if not response.ok:
                            if message := response.headers.get("message"):
                                print(message)
                            print(f"[{datetime.now()}][{self.worker_name}] API returned status code {response.status_code}")
                            raise Exception()
                    except:
                        traceback.print_exc()
                        sleep_time = min(600, sleep_time + 6)
                        print(f"[{datetime.now()}][{self.worker_name}] Sleep for {sleep_time} seconds before making another request.")
                        sleep(sleep_time)
                        continue

                    # reset sleep_time when request is successful
                    sleep_time = 0

                    json_data: dict = response.json()
                    result: list = json_data[self.data_key]
                    number_of_results = len(result)
                    if result:
                        print(f"[{datetime.now()}][{self.worker_name}] Downloaded item {index} to {index+number_of_results}, out of {json_data["totalResults"]} items. (request took {seconds_took} seconds.)")
                        index += number_of_results
                        yield result
                    elif  index >= json_data["totalResults"]:
                        if index:
                            print(f"[{datetime.now()}][{self.worker_name}] All {json_data["totalResults"]} entries downloaded")
                        else:
                            print(f"[{datetime.now()}][{self.worker_name}] No new data")
                        self.finished = True
                        return
                    else:
                        print(f"[{datetime.now()}][{self.worker_name}] API worker is stuck (more data is expected but server provided no data)")
                        self.critical_failure = True
                        self.finished = True
                        return
        except:
            print(f"[{datetime.now()}][{self.worker_name}] API worker encountered critical failure!")
            traceback.print_exc()
            self.critical_failure = True
            self.finished = True

async def cve_download(
        tag: str,
        API_path: str,
        data_key: str,
        layer2_data_key: str,
        entry_id_key: str,
        since_parameter_name: str,
        until_parameter_name: str
        ) -> int:
    since = None
    if Path(f"{tag}/since").exists():
        with Path(f"{tag}/since").open() as timestamp_file:
            since = datetime.fromtimestamp(int(timestamp_file.readline()), tz=timezone.utc)
    
    worker = APIWorker(tag, API_path, data_key, since_parameter_name, until_parameter_name, since)
    try:
        processed_items = 0
        async for list_of_entries in worker.run():
            print(f"[{datetime.now()}][{tag}] saving item {processed_items} to {processed_items + len(list_of_entries)}")
            for entry in list_of_entries:
                #print(entry[layer2_data_key])
                cve_id = CVE_pattern.match(entry[layer2_data_key][entry_id_key])
                cve_year = cve_id.group("year")
                cve_number = cve_id.group("number")
                crossed_number = cve_number[:-3] + "xxx"
                Path(f"{tag}/{cve_year}/{crossed_number}").mkdir(parents=True, exist_ok=True)
                if tag == "NVD":
                    json_filepath = f"{tag}/{cve_year}/{crossed_number}/{cve_id.group(0)}.json"
                elif tag == "CVE_history":
                    # include timestamp in filename becuase a CVE might have multiple changes
                    timestamp = int(datetime.fromisoformat(entry[layer2_data_key]["created"]).astimezone(timezone.utc).timestamp())
                    json_filepath = f"{tag}/{cve_year}/{crossed_number}/{cve_id.group(0)}-{timestamp}.json"
                with Path(json_filepath).open(mode="wb") as result_file:
                    result_file.write(orjson.dumps(entry[layer2_data_key], option=orjson.OPT_INDENT_2))
            print(f"[{datetime.now()}][{tag}] saved {len(list_of_entries)} items.")
            processed_items += len(list_of_entries)
        if not worker.critical_failure and processed_items:
            with Path(f"{tag}/since").open(mode="w") as timestamp_file:
                timestamp_file.write(str(worker.until_timestamp))
        return processed_items
    except:
        traceback.print_exc()
        raise

def sanitize_pathname(path: str):
    if path.startswith("."):
        # on linux a directory name starts with "." is hidden
        path = "_" + path
    # list of characters that might be problematic with file systems
    # https://stackoverflow.com/a/31976060
    character_blackllist = "/\\<>:\"|?*" + chr(0)
    for character in character_blackllist:
        path = path.replace(character, "_")
    upper_path_name = path.upper()
    if upper_path_name in ["CON", "PRN", "AUX", "NUL", ".", ".."] or re.match(r"(COM|LPT)\d", upper_path_name):
        path = "_" + path
    return path

async def product_download(
        tag: str,
        API_path: str,
        data_key: str,
        layer2_data_key: str,
        cpe_key: str,
        match_criteria_key: str,
        since_parameter_name: str,
        until_parameter_name: str
    ) -> int:
    since = None
    if Path(f"{tag}/since").exists():
        with Path(f"{tag}/since").open() as timestamp_file:
            since = datetime.fromtimestamp(int(timestamp_file.readline()), tz=timezone.utc)
    
    worker = APIWorker(tag, API_path, data_key, since_parameter_name, until_parameter_name, since)
    try:
        processed_items = 0
        async for list_of_entries in worker.run():
            print(f"[{datetime.now()}][{tag}] saving item {processed_items} to {processed_items + len(list_of_entries)}")
            for entry in list_of_entries:
                #print(entry[layer2_data_key])
                cpe: str = entry[layer2_data_key][cpe_key]
                cpe_array = cpe.split(":")
                vendor = sanitize_pathname(cpe_array[3])
                product = sanitize_pathname(cpe_array[4])
                dir_path = Path(f"{tag}/{vendor[0]}/{vendor}/{product}")
                dir_path.mkdir(parents=True, exist_ok=True)
                json_filepath = dir_path / f"{entry[layer2_data_key][match_criteria_key]}.json"
                with Path(json_filepath).open(mode="wb") as result_file:
                    result_file.write(orjson.dumps(entry[layer2_data_key], option=orjson.OPT_INDENT_2))
            print(f"[{datetime.now()}][{tag}] saved {len(list_of_entries)} items.")
            processed_items += len(list_of_entries)
        if not worker.critical_failure and processed_items:
            with Path(f"{tag}/since").open(mode="w") as timestamp_file:
                timestamp_file.write(str(worker.until_timestamp))
        return processed_items
    except:
        traceback.print_exc()
        worker.queue.shutdown()
        raise

async def main():
    async with asyncio.TaskGroup() as tg:
        task1 = tg.create_task(cve_download("NVD", "rest/json/cves/2.0", "vulnerabilities", "cve", "id", "lastModStartDate", "lastModEndDate"))
        task2 = tg.create_task(cve_download("CVE_history", "rest/json/cvehistory/2.0", "cveChanges", "change", "cveId", "changeStartDate", "changeEndDate"))
        task3 = tg.create_task(product_download("CPE", "rest/json/cpes/2.0", "products", "cpe", "cpeName", "cpeNameId", "lastModStartDate", "lastModEndDate"))
        task4 = tg.create_task(product_download("MacthCriteria", "rest/json/cpematch/2.0", "matchStrings", "matchString", "criteria", "matchCriteriaId", "lastModStartDate", "lastModEndDate"))
    processed_items = task1.result() + task2.result() + task3.result() + task4.result()
    if processed_items:
        print("making git commit")
        subprocess.run(["/usr/bin/env", "git", "add", "-A"], check=True)
        subprocess.run(["/usr/bin/env", "git", "commit", "-a", "-m", f"{processed_items} items changed"], check=True)
        subprocess.run(["/usr/bin/env", "git", "push"], check=True)

if __name__ == "__main__":
    asyncio.run(main())
    # loop =asyncio.new_event_loop()
    # try:
    #     loop.run_until_complete(main())
    # except (asyncio.CancelledError, KeyboardInterrupt):
    #     for task in asyncio.all_tasks(loop):
    #         task.cancel()