import argparse
import subprocess
import logging
import sys
from ipwhois import IPWhois
import json

# Colours for console output

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Single whois lookup

def whois_single(domain):
    obj = IPWhois(domain)
    res = obj.lookup_whois(inc_nir=True)
    output = json.dumps(res)
    result = []
    for line in output.split('\n', 1):
        result.append(line)
    return result

# Multiple inputs

def whois_multiple(domains):
  result = []
  for domain in domains:
    result += whois_single(domain)
  return result

# Read external file with list

def read_filename(filename):
  result = []
  with open(filename) as f:
    for line in f:
      line = line.strip()
      if line.startswith("#") or line == "":
        continue
      result.append(line)
  return result

def main():
    # Argument Parser

    parser = argparse.ArgumentParser(description="Run WhoisCheck for IP addresses", usage="python LinuxIPWhois.py", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", dest="single", help="Single IP to check, example = -s 216.58.213.14")
    parser.add_argument("-f", dest="filename",
                        help="File to be checked with one IP per line")
    args = parser.parse_args()

    # Configure logging

    logging.basicConfig(filename='WhoisIPLookup.log', level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(name)s %(message)s')
    logger = logging.getLogger(__name__)

    try:
        1 / 0
    except ZeroDivisionError as err:
        logger.error(err)

    # Perform whois lookups and output results

    if args.single is not None:
        results = whois_single(args.single)
        # print(bcolors.OKBLUE + "WhoIS:" + "\n" + "\n" + str(results) + "\n" + bcolors.ENDC)
        with open('Results.txt', 'a') as outfile:
            to_json = json.dumps(results)
            test = json.dump(to_json, outfile)
            print(test)

    elif args.filename is not None:
        domains = whois_multiple(read_filename(args.filename))
        # print(bcolors.OKBLUE + "WhoIS" + "\n" + "\n" + str(domains) + "\n" + bcolors.ENDC)
        with open('Results.txt', 'a') as outfile:
            outfile.write(repr(domains))


if __name__ == "__main__":
    main()
