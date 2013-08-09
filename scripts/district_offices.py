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
import os
import datetime
import hashlib
import pprint
import time
import cPickle as pickle
from pygeocoder import Geocoder
from utils import download, load_data, save_data, parse_date
import lxml.html, lxml.etree, StringIO
import requests
import urlparse

debug = False
cache = False
debug_bioguide = None

re_phone = re.compile(r'(?P<areacode>\(\d{3}\)|\d{3})?\s{0,20}[\.\-\s]\s{0,20}(?P<prefix>\d{3})\s*[\.\-\s]\s*(?P<suffix>\d{4})', re.MULTILINE|re.DOTALL)
re_zipcode = re.compile(r'[^\d](\d{5}(\-\d{4})?)', (re.MULTILINE|re.DOTALL)) 
re_office = re.compile(r'office', re.IGNORECASE)

def strip_tags(html):
  return re.sub(r'<\/?[^>]*>', r'', html).strip()

def normalize_phone_number(phone_number):
  match = re_phone.search(phone_number)
  if match:
    return re.sub(r'[^\d\-]','',"%s-%s-%s" % (match.group('areacode'), match.group('prefix'), match.group('suffix')))
  else:
    return phone_number

def detect_possible_office_elements(member, url, body):

  state = member.get('state', 'XX')
  url = member.get('url', None)

  root = lxml.html.parse(StringIO.StringIO(body)).getroot()

  possible_office_matches = {}

  # collect every element in the DOM that has a ZIP, phone number and the legislator's state
  for element in root.iter(tag=lxml.etree.Element):
    element_text = None
    element_html = None
    try:
      # element_text = lxml.etree.tostring(element, method='text').encode('utf-8')
      element_html = lxml.etree.tostring(element)
      element_text = strip_tags(element_html)
    except:
      continue

    possible_office_match = re_office.search(element_text)
    possible_zipcode_matches = re_zipcode.findall(element_html)
    possible_phone_matches = re_phone.search(element_text)
    state_present = re.search(r'\s*(?P<state>%s|%s|D\.?C\.?|District\s+of\s+Columbia)' % (utils.states[state.upper()], state), element_text, re.IGNORECASE)   

    if possible_zipcode_matches:
      clue_count = 0
      for i in ((possible_office_match is not None), (len(possible_zipcode_matches)==1), (possible_phone_matches is not None), (state_present is not None)):
        if i:          
          clue_count = clue_count + 1
    

      if clue_count>=3: # if we find 3/4 matching criteria, we run with it
        # check to ensure we haven't already added this element -- use zip and phone as keys
        z_key = ''.join(possible_zipcode_matches[0]).strip()
        p_key = possible_phone_matches and re.sub(r'[^\d]','',possible_phone_matches.group(0).strip()) or ''
        possible_office_matches["%s/%s" % (z_key, p_key)] = (element, {
          '_scraped': True,
          '_scraped_date': datetime.datetime.now().isoformat(),
          '_scraped_url': url,
        })          

  return possible_office_matches


def extract_info_from_office_elements(member, possible_office_matches):
  state = member.get('state', 'XX')  

  extracted_offices = []

  # process each (hopefully!) distinct match
  for (key, (element, meta)) in possible_office_matches.items():  

    extracted_info = {}      
           
    match_html = lxml.etree.tostring(element)

    # remove other junk
    match_html = re.sub('(&nbsp;|&#160;)',' ', re.sub(r'&#13;','',match_html)).strip()
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
    re_state = re.compile(r',\s*(?P<state>%s|%s|D\.?C\.?|District\s+of\s+Columbia)' % (utils.states[state.upper()], state), flags=re.IGNORECASE)
    for i in range(len(match_lines)-1, -1, -1):
      zipcode_match = re_zipcode.search(strip_tags(match_lines[i]))
      if zipcode_match:
        found_zip = True  
        # extract city, state, zip
        extracted_info['zipcode'] = re.sub(r'[^\d\-]','',zipcode_match.group(0).strip())
        state_match = re_state.search(strip_tags(match_lines[i].replace(extracted_info['zipcode'],'')))
        if state_match:
          extracted_info['state'] = state_match.group('state')
        extracted_info['city'] = re_state.sub('', strip_tags(match_lines[i].replace(extracted_info['zipcode'],'')))
      elif found_zip:
        if len(strip_tags(match_lines[i]))>0:
          address_lines.insert(0, match_lines[i])                


    # wait a minute. how many address lines did we find? if it's more than 5, chuck it out -- we're
    # almost certainly capturing incidental HTML
    if len(address_lines)>=5:
      continue

    # do we have address_lines[0] (non-numeric) and address_lines[1] (numeric) and no label? if so...
    if len(address_lines)>1:
      if re.search(r'^[^\d]', strip_tags(address_lines[0])) and re.search(r'^\d', strip_tags(address_lines[1])) and (len(extracted_info.get('label',''))==0):
        extracted_info['label'] = strip_tags(address_lines.pop(0))

    # convert our array of address elements into named fields
    for (i,al) in enumerate(address_lines):
      extracted_info['address_%d' % i] = strip_tags(al)

    # add back in the scraping metadata
    extracted_info.update(meta)

    # append the record to our output set
    extracted_offices.append(extracted_info.copy())


  # DEDUPLICATION (occasional artifact of lxml tree traversal)

  # kill empty fields
  for office in extracted_offices:
    for (key, value) in office.items():
      if type(value) is str and len(value.strip())==0:
        del office[key]

  # run through extracted_offices (n^2), detecting any that are subsets of others
  duplicate_office_indices = []
  for (i,office) in enumerate(extracted_offices):
    for comparison_office in extracted_offices:
      all_fields_identical = True
      for (key, value) in office.items():
        if not key.startswith('_'): # ignore meta fields      
          if value!=comparison_office.get(key, None):
            all_fields_identical = False  

      if all_fields_identical and (len(office.keys())<len(comparison_office.keys())):
        if i not in duplicate_office_indices:
          duplicate_office_indices.append(i)
  
  # removed detected duplicates
  for i in sorted(duplicate_office_indices, reverse=True):
    extracted_offices.pop(i)

  return extracted_offices

def rewrite_link_to_absolute_url(root_url, link):    
  if link is None:
    return False
  if link.startswith('mailto:') or link.startswith('javascript:'):
    return False
  if link.startswith('http://'):
    return link
  return urlparse.urljoin(root_url, link)  


def sweep():
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

    # grab the front page of the website
    if debug:
      print "[%s] Downloading home page..." % bioguide
    cache = "congress/%s.html" % bioguide

    # fetch the HTML
    body = utils.download(url, cache, force, {'check_redirects': True})
    
    # check the front page for district office addresses
    possible_office_matches = {}
    possible_office_matches.update( detect_possible_office_elements(current_bioguide[bioguide]["terms"][-1], url, body) )
    
    # no match? walk the links on the page looking for "district office", then "contact"    
    if len(possible_office_matches)==0:
      re_subpage_detectors = (re.compile(r'district\s+office', re.IGNORECASE|re.MULTILINE|re.DOTALL), re.compile(r'contact', re.IGNORECASE|re.MULTILINE|re.DOTALL))  
      for re_detector in re_subpage_detectors:
        root = lxml.html.parse(StringIO.StringIO(body)).getroot()
        candidate_urls = {}
        for element in root.iter('a'):
          if element.text is None:
            continue          
          if re_detector.search(element.text):            
            district_office_url = rewrite_link_to_absolute_url(url, element.get('href', None))
            if district_office_url:
              candidate_urls[district_office_url] = True

        # download the detected URL(s) and look for matching elements
        for candidate_url in candidate_urls.keys():
          if debug:
            print "[%s] Downloading %s..." % (bioguide, district_office_url)
          cache = "congress/%s-%s.html" % (bioguide, hashlib.sha256(candidate_url).hexdigest())
          district_office_body = utils.download(candidate_url, cache, force, {'check_redirects': True})
          possible_office_matches.update( detect_possible_office_elements(current_bioguide[bioguide]["terms"][-1], candidate_url, district_office_body) )

        # did we find some plausible district office addresses? if so, break
        if len(possible_office_matches)>0:
          break
      
    # still no match? mark it as requiring review:
    if len(possible_office_matches)==0:
      if not output.has_key(bioguide):
        output[bioguide] = {'_requires_manual_intervention': True, 'url': url}

    # otherwise, extract the individual fields for offices and store them
    extracted_offices = extract_info_from_office_elements(current_bioguide[bioguide]["terms"][-1], possible_office_matches)
    if len(extracted_offices)>0:
      output[bioguide] = extracted_offices

  # save our work
  if debug_bioguide is None:
    print "Saving data..."
    save_data(output, "legislators-district-offices.yaml")
  else:
    pprint.pprint(output)

  return output


  # print out the number we're up to
  member_count = 0
  office_count = 0
  for b in output:
    if type(output[b]) is list:    
      member_count = member_count + 1
      for office in output[b]:
        office_count = office_count + 1  
  print "Found %d offices for %d members out of %d" % (office_count, member_count, len(current_bioguide))
   
def verify():
  pass     

def office_address_string(office):
  address = []
  i = 0
  while office.has_key('address_%d' % i):
    address.append(office.get('address_%d' % i))
    i = i + 1
  address.append('%s, %s' % (office.get('city', ''), office.get('state', '')))
  address.append(office.get('zipcode', ''))
  return ' '.join(address)

def office_hash(bioguide, office):
  h = [bioguide]
  for (k,v) in office.items():
    if not k.startswith('_') and k!='hours': # excluding hours is a hack to keep my geocoding data current
      h.append('%s:%s' % (k,v))
  return hashlib.sha256('#'.join(h)).hexdigest()

def geocode(offices):
  for bioguide in offices:    
    for office in offices[bioguide]:  

      # skip obviously incomplete or broken records  
      if type(office) is not dict:
        continue
      if not(office.has_key('address_0') and office.has_key('city') and office.has_key('state') and office.has_key('zipcode')):
        continue

      # skip previously geocoded offices
      ohash = office_hash(bioguide, office)
      opath = 'data/geocode/%s.pickle' % ohash
      if os.path.exists(opath):
        print '[%s] Skipping previously geocoded office...' % (bioguide)
        continue

      # assemble the address string
      address_string = office_address_string(office)

      # geocode
      print '[%s] Geocoding \'%s\'' % (bioguide, address_string)      
      try:
        geocoder_results = Geocoder.geocode(address_string)
      except Exception, e:
        # problem? continue on, blissfully unaware of the problem
        continue

      # store the result(s)
      f = open(opath, 'w')
      pickle.dump(geocoder_results.raw, f)
      f.close()

      # give google a little break
      time.sleep(0.5)


if __name__ == '__main__':

  debug = utils.flags().get('debug', False)
  cache = utils.flags().get('cache', False)
  debug_bioguide = utils.flags().get('bioguide', None)

  offices = None

  if utils.flags().get('sweep', False):
    offices = sweep()
  if utils.flags().get('geocode', False):
    if offices is None:
      offices = utils.load_data("legislators-district-offices.yaml")
      geocode(offices)

  if utils.flags().get('verify', False):
    verify()



