#!/usr/bin/env python

# run with --sweep (or by default):
#   given a service, looks through current members for those missing an account on that service,
#   and checks that member's official website's source code for mentions of that service.
#   A CSV of "leads" is produced for manual review.
#
# run with --update:
#   reads the CSV produced by --sweep back in and updates the YAML accordingly.
#
# run with --clean:
#   removes legislators from the social media file who are no longer current
#
# run with --resolvefb:
#   finds both Facebook usernames and graph IDs and updates the YAML accordingly.
#
# run with --resolveyt:
#   finds both YouTube usernames and channel IDs and updates the YAML accordingly.

# other options:
#  --service (required): "twitter", "youtube", or "facebook"
#  --bioguide: limit to only one particular member
#  --email:
#      in conjunction with --sweep, send an email if there are any new leads, using
#      settings in scripts/email/config.yml (if it was created and filled out).

# uses a CSV at data/social_media_blacklist.csv to exclude known non-individual account names

import csv
import re
import utils
import datetime
from utils import download, load_data, save_data, parse_date
import lxml.html, lxml.etree, StringIO
import requests

re_phone = re.compile(r'((?P<areacode>\(\d{3}\)|\d{3})?[\.\-\s](?P<prefix>\d{3})[\.\-\s](?P<suffix>\d{4}))')
re_zipcode = re.compile(r'[^\d](\d{5}(\-\d{4})?)[$\s<]', (re.MULTILINE|re.DOTALL))
re_phone_in_html = re.compile(r'[^\(\d]((\(\d{3}\)|\d{3})?[\.\-\s]\d{3}[\.\-\s]\d{4})[$\s<]', (re.MULTILINE|re.DOTALL))
re_zipcode_cleaned = re.compile(r'[^\d](\d{5}(\-\d{4})?)') 

def strip_tags(html):
  return re.sub(r'<\/?[^>]*>', r'', html).strip()

def normalize_phone_number(phone_number):
  match = re_phone.search(phone_number)
  if match:
    return re.sub(r'[^\d\-]','',"%s-%s-%s" % (match.group('areacode'), match.group('prefix'), match.group('suffix')))
  else:
    return phone_number

def detect_possible_office_elements(member, body):
  debug = utils.flags().get('debug', False)
  cache = utils.flags().get('cache', False)
  debug_bioguide = utils.flags().get('bioguide', None)

  state = member.get('state', 'XX')
  url = member.get('url', None)

  root = lxml.html.parse(StringIO.StringIO(body)).getroot()

  possible_office_matches = {}

  # collect every element in the DOM that has a ZIP, phone number and the legislator's state
  for element in root.iter(tag=lxml.etree.Element):
    element_text = None
    element_html = None
    try:
      element_text = lxml.etree.tostring(element, method='text').encode('utf-8')
      element_html = lxml.etree.tostring(element)
    except:
      continue

    possible_zipcode_matches = re_zipcode.findall(element_html)
    possible_phone_matches = re_phone_in_html.search(element_html)
    state_present = re.search(r'\W(%s|%s)\W' % (state, utils.states[state.upper()]), element_text, re.IGNORECASE)   

    if possible_zipcode_matches:
      if len(possible_zipcode_matches)==1 and possible_phone_matches and state_present:          
        # check to ensure we haven't already added this element -- use zip and phone as keys
        key = "%s/%s" % (''.join(possible_zipcode_matches[0]).strip(), re.sub(r'[^\d]','',possible_phone_matches.group(0).strip()))          
        possible_office_matches[key] = element

  return possible_office_matches


def extract_info_from_office_elements(member, possible_office_matches):
  state = member.get('state', 'XX')
  url = member.get('url', None)

  extracted_offices = []

  # process each (hopefully!) distinct match
  for (key,match) in possible_office_matches.items():  

    extracted_info = {}      
           
    match_html = lxml.etree.tostring(match)
    # remove other junk
    match_html = re.sub('&nbsp;',' ', re.sub(r'&#13;','',match_html)).strip()
    # remove CSS & JS
    match_html = re.sub('<script[^>]*>.*?<\/script[^>]*>', '', match_html, flags=(re.MULTILINE|re.DOTALL|re.IGNORECASE))
    match_html = re.sub('<style[^>]*>.*?<\/style[^>]*>', '', match_html, flags=(re.MULTILINE|re.DOTALL|re.IGNORECASE))
    # turn a close/open div pair into a <br/> -- hacky!
    match_html = re.sub(r'<\/div>\s*<div[^>]*>', '\n', match_html, flags=(re.MULTILINE|re.IGNORECASE|re.DOTALL))
    # convert <br/>'s into newlines
    match_html = re.sub(r'<\s*br[^>]*>', '\n', match_html, flags=(re.MULTILINE|re.IGNORECASE|re.DOTALL))
    # break into lines & strip
    match_lines = map(lambda x: x.strip(), re.split(r'\n+', match_html))
    # remove HTML-only lines
    for (i,line) in enumerate(match_lines):
      if len(strip_tags(line))==0:
        match_lines.pop(i)

    # now start to pick apart the address lines, beginning at the edges...
    
    # first: sanity check
    if len(match_lines)==0:
      continue

    # is the first line a label?
    if re.search(r'(<h\d|<strong|office:?)', match_lines[0], flags=re.I):
      extracted_info['label'] = re.sub(r'\:\s*$','',strip_tags(match_lines.pop(0)))
      if len(match_lines)==0:
        continue

    # is there a map link?
    for (i, line) in enumerate(match_lines):
      map_match = re.search(r'["\'\(](http\:\/\/maps\.google\.com[^"\'\)]*)["\'\)]', line)
      if map_match:
        extracted_info['map_link'] = map_match.group(1)
        match_lines.pop(i)
        break      
    if len(match_lines)==0:
      continue      

    # is the last line a fax number? 
    for (i,line) in enumerate(match_lines):
      m_phone = re_phone.search(line)
      if m_phone and re.search(r'(fax:?|\(f\))', line, re.I):
        extracted_info['fax'] = normalize_phone_number(strip_tags(m_phone.group(0)))
        match_lines.pop(i)
        break
    if len(match_lines)==0:
      continue
    
    # how about just a phone number?
    for (i,line) in enumerate(match_lines):
      m_phone = re_phone.search(line)
      if m_phone:
        extracted_info['phone'] = normalize_phone_number(strip_tags(m_phone.group(0)))
        match_lines.pop(i)
        break
    if len(match_lines)==0:
      continue
    
    # walk the remaining lines in reverse order. once we find a zip, start
    # assembling the address
    address_lines = []
    found_zip = False
    for i in range(len(match_lines)-1, -1, -1):
      zipcode_match = re_zipcode_cleaned.search(match_lines[i])
      if zipcode_match:
        found_zip = True  
        # extract city, state, zip
        extracted_info['zipcode'] = re.sub(r'[^\d]','',zipcode_match.group(0).strip())
        extracted_info['city'] = re.sub(r',\s*(%s|%s)' % (utils.states[state.upper()], state),'',strip_tags(match_lines[i].replace(extracted_info['zipcode'],'')), flags=re.IGNORECASE)
        extracted_info['state'] = state # assume all district offices are in-state
      elif found_zip:
        if len(strip_tags(match_lines[i]))>0:
          address_lines.insert(0, match_lines[i])                

    for (i,al) in enumerate(address_lines):
      extracted_info['address_%d' % i] = strip_tags(al)

    extracted_info['scraped'] = True
    extracted_info['scraped_date'] = datetime.datetime.now().isoformat()
    extracted_info['scraped_url'] = url

    extracted_offices.append(extracted_info.copy())

  return extracted_offices

def main():
  debug = utils.flags().get('debug', False)
  cache = utils.flags().get('cache', False)
  debug_bioguide = utils.flags().get('bioguide', None)
  force = not cache

  # load in members, orient by bioguide ID
  print "Loading current legislators..."
  current = load_data("legislators-current.yaml")

  current_bioguide = { }
  for m in current:
    if m["id"].has_key("bioguide") and ((debug_bioguide is None) or (debug_bioguide==m["id"]["bioguide"])):
      current_bioguide[m["id"]["bioguide"]] = m

  output = {}

  # iterate through current members of congress
  for bioguide in current_bioguide.keys():
    url = current_bioguide[bioguide]["terms"][-1].get("url", None)
    if not url:
      if debug:
        print "[%s] No official website, skipping" % bioguide
      return None

    if debug:
      print "[%s] Downloading..." % bioguide
    cache = "congress/%s.html" % bioguide

    # fetch the HTML
    body = utils.download(url, cache, force, {'check_redirects': True})
    
    # check the front page for district office addresses
    possible_office_matches = detect_possible_office_elements(current_bioguide[bioguide]["terms"][-1], body)
      
    # no match? 
    
    # TODO: walk links on page looking for "district office"

    # TODO: still no match? walk links looking for "contact"

    # still no match? mark it as requiring review:
    if len(possible_office_matches)==0:
      if not output.has_key(bioguide):
        output[bioguide] = {'requires_manual_intervention': True, 'url': url}

    # otherwise, extract the individual fields for offices and store them
    extracted_offices = extract_info_from_office_elements(current_bioguide[bioguide]["terms"][-1], possible_office_matches)
    if len(extracted_offices)>0:
      output[bioguide] = extracted_offices

  # save our work
  if debug_bioguide is None:
    print "Saving data..."
    save_data(output, "legislators-district-offices.yaml")
  else:
    print output


  # print out the number we're up to
  member_count = 0
  office_count = 0
  for b in output:
    if type(output[b]) is list:    
      member_count = member_count + 1
      for office in output[b]:
        office_count = office_count + 1  
  print "Found %d offices for %d members out of %d" % (office_count, member_count, len(current_bioguide))
        

if __name__ == '__main__':
  main()

