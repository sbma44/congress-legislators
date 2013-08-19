#!/usr/bin/env python

# --scrape
#   attempts to collect office information from congressional websites. 
#   options: --cache, --debug, --bioguide (latter for debugging a single member)
#   NOTE: expect the cached fragments to occupy a few hundred MB

# --geocode
#   Geocodes retrieved offices against Google's API, caches results
#   Expect the cache to occupy a couple dozen MB.

# --verify
#   Tests geocoding results against the Sunlight Congress API to determine whether offices
#   are located in the states/districts of the representative. Requires a SUNLIGHT_API_KEY
#   to be specified in settings.py or local_settings.py. See http://sunlightfoundation.com/api 
#   for more details/to obtain a free key.

# --remove-dc
#   Removes offices located in Washington, D.C. There are better/canonical sources for
#   D.C. office addresses.

# --review
#   Launches interactive/curses-based address reviewing tool. Sorts addresses into 
#   files that will require additional intervention and ones that are ready for use.

import csv
import json
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
import curses
import math
import microtron
from settings import *

debug = False
cache = False
debug_bioguide = None

re_phone = re.compile(r'(?P<areacode>\(\d{3}\)|\d{3})?\s{0,20}[\.\-\s]\s{0,20}(?P<prefix>\d{3})\s*[\.\-\s]\s*(?P<suffix>\d{4})', re.MULTILINE|re.DOTALL)
re_zipcode = re.compile(r'[^\d](\d{5}(\-\d{4})?)', (re.MULTILINE|re.DOTALL)) 
re_office = re.compile(r'office', re.IGNORECASE)

LOCKFILE = '.districtofficesavelock'

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

  # look for hCards
  formats = lxml.etree.parse('microformats.xml')
  microformat_parser = microtron.Parser(root, formats)
  mf_results = microformat_parser.parse_format('vcard')  
  if len(mf_results)==0:
    mf_results = microformat_parser.parse_format('adr') # fall back to less impressive option    
  for r in mf_results:
    source_hash = hashlib.sha256(str(r)).hexdigest()
    possible_office_matches[source_hash] = (r.copy(), {
          '_scraped': True,
          '_scraped_date': datetime.datetime.now().isoformat(),
          '_scraped_url': url,
          '_source_hash': source_hash,
          '_microformat_result': True
        })
  if len(possible_office_matches)>0:
    return possible_office_matches

  # examine every element in the DOM for address-y-ness
  for element in root.iter(tag=lxml.etree.Element):
    element_text = None
    element_html = None
    try:
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
        source_hash = hashlib.sha256(element_html).hexdigest()
        possible_office_matches["%s/%s" % (z_key, p_key)] = (element, {
          '_scraped': True,
          '_scraped_date': datetime.datetime.now().isoformat(),
          '_scraped_url': url,
          '_source_hash': source_hash,
          '_microformat_result': False
        })

        # store the HTML fragment for debugging purposes
        # store the result(s)
        f = open('data/source/%s.html' % source_hash, 'w')
        pickle.dump(element_html, f)
        f.close()

  return possible_office_matches


def extract_info_from_html_element(state, element, meta):

  extracted_info = {}      
           
  match_html = lxml.etree.tostring(element)

  # remove other junk
  match_html = re.sub('(&nbsp;|&#160;)',' ', re.sub(r'&#13;','',match_html)).strip()
  match_html = re.sub('&amp;', '&', match_html, flags=re.IGNORECASE)
  # remove CSS & JS
  match_html = re.sub('<script[^>]*>.*?<\/script[^>]*>', '', match_html, flags=(re.MULTILINE|re.DOTALL|re.IGNORECASE))
  match_html = re.sub('<style[^>]*>.*?<\/style[^>]*>', '', match_html, flags=(re.MULTILINE|re.DOTALL|re.IGNORECASE))
  # turn a close/open div pair into a <br/> -- hacky!
  match_html = re.sub(r'<\/div>\s*<div[^>]*>', '\n', match_html, flags=(re.MULTILINE|re.IGNORECASE|re.DOTALL))
  # convert <br/>'s and <p>'s into newlines
  match_html = re.sub(r'<\s*(br|p)[^>]*>', '\n', match_html, flags=(re.MULTILINE|re.IGNORECASE|re.DOTALL))
  # break into lines & strip
  match_lines = map(lambda x: x.strip(), re.split(r'\n+', match_html))
  # remove HTML-only lines
  for (i,line) in enumerate(match_lines):
    if len(strip_tags(line))==0:
      match_lines.pop(i)

  # now start to pick apart the address lines, beginning at the edges...
  
  # first: sanity check
  if len(match_lines)==0:
    return None

  # is the first line a label?
  if re.search(r'(<h\d|<strong|office:?)', match_lines[0], flags=re.I):
    extracted_info['label'] = re.sub(r'\:\s*$','',strip_tags(match_lines.pop(0)))

  # is there a map link?
  for (i, line) in enumerate(match_lines):
    map_match = re.search(r'["\'\(](http\:\/\/maps\.google\.com[^"\'\)]*)["\'\)]', line)
    if map_match:
      extracted_info['map_link'] = map_match.group(1)
      match_lines.pop(i)
      break      

  # office hours?
  for (i, line) in enumerate(match_lines):
    found_am = re.search(r'\d\s*a\.?m\.?\W', line, flags=re.IGNORECASE)
    found_pm = re.search(r'\d\s*p\.?m\.?\W', line, flags=re.IGNORECASE)
    found_hours = re.search(r'\Whours[\:\s\W]', line, flags=re.IGNORECASE)
    clue_count = 0
    for x in (found_am, found_pm, found_hours):
      if x:
        clue_count = clue_count + 1
    if clue_count>=2:
      extracted_info['hours'] = re.sub(r'^hours\:?\s+', '', strip_tags(match_lines.pop(i)), flags=re.IGNORECASE)
      break

  # is there a fax number? 
  for (i,line) in enumerate(match_lines):
    m_phone = re_phone.search(line)
    if m_phone and re.search(r'(fax:?|\(f\)|\Wf\.)', line, re.I):
      extracted_info['fax'] = normalize_phone_number(strip_tags(m_phone.group(0)))
      match_lines.pop(i)
      break
  
  # how about just a phone number?
  for (i,line) in enumerate(match_lines):
    m_phone = re_phone.search(line)
    if m_phone:
      extracted_info['phone'] = normalize_phone_number(strip_tags(m_phone.group(0)))
      match_lines.pop(i)
      break
  
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
    return None

  # do we have address_lines[0] (non-numeric) and address_lines[1] (numeric) and no label? if so...
  if len(address_lines)>1:
    if re.search(r'^[^\d]', strip_tags(address_lines[0])) and re.search(r'^\d', strip_tags(address_lines[1])) and (len(extracted_info.get('label',''))==0):
      extracted_info['label'] = strip_tags(address_lines.pop(0))

  # convert our array of address elements into named fields
  for (i,al) in enumerate(address_lines):
    extracted_info['address_%d' % i] = strip_tags(al)

  # add back in the scraping metadata
  extracted_info.update(meta)
  
  return extracted_info


def extract_info_from_microformat_result(element, meta):
  extracted_info = {}
  adr = element
  if element.get('__type__')=='vcard':
    extracted_info['label'] = "\n".join(element.get('org', ''))
    if len(element.get('tel', []))>0:
      for t in element.get('tel'):
        if type(t) is dict:
          t_type = ' '.join(t.get('type')).upper()
          if 'FAX' in t_type:
            extracted_info['fax'] = t.get('value', '')
          if 'PHONE' in t_type:
            extracted_info['phone'] = t.get('value', '')
    else:
      extracted_info['phone'] = "\n".join(element.get('tel', []))
    adr = element.get('adr', [{}])[0]
  extracted_info['city'] = adr.get('locality', '')
  extracted_info['state'] = adr.get('region', '')
  extracted_info['zipcode'] = adr.get('postal-code', '')
  for (i, a) in enumerate(adr.get('street-address', [])):
    extracted_info['address_%d' % i] = a

  extracted_info.update(meta)

  return extracted_info

def extract_info_from_office_elements(member, possible_office_matches):
  state = member.get('state', 'XX')  

  extracted_offices = []

  # process each (hopefully!) distinct match
  for (key, (element, meta)) in possible_office_matches.items():  

    extracted_info = {}
    if meta.get('_microformat_result', False):
      extracted_info = extract_info_from_microformat_result(element, meta)
    else:
      extracted_info = extract_info_from_html_element(state, element, meta)
    
    # append the record to our output set
    if extracted_info is not None:
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


def scrape():
  """ Scrapes congressional websites, trying multiple URLs when
  necessary and making informed guesses about where district office info
  can be found. """

  # make HTML fragment caching directory
  utils.mkdir_p('data/source')

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
  flagged = {}

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
        flagged[bioguide] = [{'_requires_manual_intervention': True, 'url': url}]

    # otherwise, extract the individual fields for offices and store them
    extracted_offices = extract_info_from_office_elements(current_bioguide[bioguide]["terms"][-1], possible_office_matches)
    if len(extracted_offices)>0:
      output[bioguide] = extracted_offices

  # save our work
  if debug_bioguide is None:
    print "Saving data..."
    save_data(output, "legislators-district-offices-unreviewed.yaml")
    save_data(flagged, 'legislators-district-offices-flagged.yaml')
  else:
    pprint.pprint(output)

  # print out the number we're up to
  member_count = 0
  office_count = 0
  for b in output:
    if type(output[b]) is list:    
      member_count = member_count + 1
      for office in output[b]:
        office_count = office_count + 1  
  print "Found %d offices for %d members out of %d" % (office_count, member_count, len(current_bioguide))
   
  return output

def verify(offices):
  """ Open each geocoded office location and attempt to determine if it's 
  in the legislator's district """
  for bioguide in offices:    
    for office in offices[bioguide]:    

      # skip obviously incomplete records        
      if not(office.has_key('address_0') and office.has_key('city') and office.has_key('state') and office.has_key('zipcode')):
        continue

      # skip DC offices
      if office['state'].upper().strip() in ('DC', 'D.C.', 'DISTRICT OF COLUMBIA'):
        continue

      # check for a previously geocoded office
      ohash = office_hash(office)
      opath = 'data/geocode/%s.pickle' % ohash
      geocoded_result = False
      if os.path.exists(opath):
        f = open(opath, 'r')
        geocoded_result = pickle.load(f)
        f.close()

      if geocoded_result:        
        coords = (geocoded_result[0]['geometry']['location']['lat'], geocoded_result[0]['geometry']['location']['lng'])
        url = 'http://congress.api.sunlightfoundation.com/legislators/locate?latitude=%f&longitude=%f&apikey=%s' % (coords[0], coords[1], SUNLIGHT_API_KEY)        
        response = requests.get(url)
        result = json.loads(response.text)

        # find every bioguide in the response
        returned_bioguide_ids = []
        for b in result.get('results',{}):
          returned_bioguide_ids.append(b['bioguide_id'])
        if bioguide in returned_bioguide_ids:
          print "[%s] Confirmed in-district office: '%s'" % (bioguide, office_address_string(office))
          office.update({'latitude': geocoded_result[0]['geometry']['location']['lat'], 'longitude': geocoded_result[0]['geometry']['location']['lng'], 'confirmed_in_district': True})
        else:
          print "[%s] District mismatch: '%s'" % (bioguide, office_address_string(office))
      else:
        print "[%s] Did not find geocoded result" % (bioguide)

  print "Saving data..."
  save_data(offices, "legislators-district-offices-unreviewed.yaml")

  return offices

def save_locked():
  return os.path.exists(LOCKFILE)

def review_prep_data_pre_save(office_list):
  output = {}
  for (bioguide, office) in office_list:
    if not output.has_key(bioguide):
      output[bioguide] = []
    output[bioguide].append(office)
  return output

def review_prep_data_post_load(data):
  output = []
  for bioguide in data:
    for office in data[bioguide]:
      output.append((bioguide, office))
  return output

def review_save(unreviewed, approved, flagged):
  if save_locked():
    return
  else:
    if os.fork()==0: # save this in a fork
      
      # create lockfile
      f = open(LOCKFILE, 'w')
      f.close()

      # reorganize data
      unreviewed_s = review_prep_data_pre_save(unreviewed)
      approved_s = review_prep_data_pre_save(approved)
      flagged_s = review_prep_data_pre_save(flagged)

      save_data(unreviewed_s, 'legislators-district-offices-unreviewed.yaml')
      save_data(approved_s, 'legislators-district-offices-approved.yaml')
      save_data(flagged_s, 'legislators-district-offices-flagged.yaml')

      # remove lock
      os.unlink(LOCKFILE)

      exit(0)

def review_draw_office(window, office):  
  (max_y, max_x) = window.getmaxyx()

  # display office under review
  FIELDS = ('label', 'address_0', 'address_1', 'address_2', 'address_3', 'address_4', 'city', 'state', 'zipcode', 'phone', 'fax', 'hours', 'map_link')
  for (row, field) in enumerate(FIELDS):
    window.addstr(row+2, 1, "%10s:" % field, curses.color_pair(2))
    window.addstr(row+2, 13, office.get(field, '')[:max_x-20], curses.color_pair(0))
  if office.has_key('confirmed_in_district'):
    window.addstr(len(FIELDS)+3, 2, "CONFIRMED IN DISTRICT", curses.color_pair(1))
  window.refresh()

def review():  

  legislators = {}
  for l in utils.load_data('legislators-current.yaml'):
    legislators[l['id']['bioguide']] = "%s %s" % (l['name']['first'], l['name']['last'])

  unreviewed = approved = flagged = {}
  try:
    unreviewed = load_data('legislators-district-offices-unreviewed.yaml')
  except Exception, e:
    pass
  try:
    approved = load_data('legislators-district-offices-approved.yaml')
  except Exception, e:
    pass
  try:
    flagged = load_data('legislators-district-offices-flagged.yaml')
  except Exception, e:
    pass
  
  # reorganize data into lists -- easier to manipulate
  unreviewed = review_prep_data_post_load(unreviewed)
  approved = review_prep_data_post_load(approved)
  flagged = review_prep_data_post_load(flagged)

  unreviewed.sort(key=lambda x: x[0]) # sort by members

  num_to_review = len(unreviewed)

  # initialize curses
  window = curses.initscr()
  curses.noecho()
  curses.cbreak()
  curses.start_color()
  curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
  curses.init_pair(2, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
  curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)
  window.keypad(1)
  window.nodelay(1)

  (max_y, max_x) = window.getmaxyx()

  quit_signal_received = False

  try:
    num_reviewed = 0
    while len(unreviewed)>0 and quit_signal_received is False:
      # clear the window
      window.erase()

      # draw menu line across bottom
      window.addstr(max_y-4, 0, "s[P]lit address     [M]ove address_0 into label      ", curses.A_REVERSE)
      window.addstr(max_y-5, 0, "[A]pprove     [F]lag     [S]ave     s[K]ip     [Q]uit", curses.A_REVERSE)

      # draw status line
      status_width = int(math.floor(max_x * (num_reviewed / (num_to_review * 1.0))))
      window.addstr(max_y-1, 0, (" " * status_width), curses.A_REVERSE | curses.color_pair(1))
      window.addstr(max_y-2, 0, "%d/%d" % (num_reviewed, num_to_review), curses.color_pair(1))
      
      (bioguide, office) = unreviewed[0]

      # draw legislator name
      window.addstr(0,3," %s  %s" % (bioguide, legislators[bioguide]), curses.color_pair(0)|curses.A_BOLD)
      window.addstr(0,3,"[", curses.color_pair(3))
      window.addstr(0,3 + len(bioguide),"]", curses.color_pair(3))

      review_draw_office(window, office)

      # grab input and file, if appropriate
      ch = -1
      ch_count = 0
      while (ch<0) and quit_signal_received is False:
        ch = window.getch()
        if ch_count==0: # no need to hammer the filesystem
          if save_locked():
            window.addstr(max_y-2, max_x-len('Saving... '), 'Saving...', curses.color_pair(1))
            window.refresh()
          else:
            window.addstr(max_y-2, max_x-len('          '), '          ', curses.color_pair(1))
            window.refresh()
        ch_count = (ch_count + 1) % 500

      if ch<256:
        c = chr(ch).upper()
        
        # quit/cleanup
        if c=='Q':
          quit_signal_received = True
          curses.nocbreak()
          window.keypad(0)
          curses.echo()
          curses.endwin()

        # save
        if c=='S':
          review_save(unreviewed, approved, flagged)          
        
        # split address
        if c=='P':
          office['state'] = re.sub(r',$', '', office.get('city','').split(' ')[-1].strip())
          office['city'] = re.sub(r',$', '', ' '.join(office.get('city', '').split(' ')[:-1]).strip())
          review_draw_office(window, office)

        # move address lines up one into label position
        if c=='M': 
          if office.has_key('address_0'):            
            office['label'] = office['address_0']
          else:
            del office['label']
          i = 0
          while office.has_key('address_%d' % (i+1)):
            office['address_%d' % i] = office['address_%d' % (i+1)]
            i = i + 1
          if office.has_key('address_%d' % i):
            del office['address_%d' % i]
          review_draw_office(window, office)

        # file away entry -- skip, accept, flag
        if c in ('F', 'A', 'K'):
          unreviewed.pop(0)
          if c=='A':
            approved.append((bioguide, office))
          if c=='F':
            flagged.append((bioguide, office))          
          num_reviewed = num_reviewed + 1

  finally:
    curses.nocbreak()
    window.keypad(0)
    curses.echo()
    curses.endwin()



def office_address_string(office):
  address = []
  i = 0
  while office.has_key('address_%d' % i):
    address.append(office.get('address_%d' % i))
    i = i + 1
  address.append('%s, %s' % (office.get('city', ''), office.get('state', '')))
  address.append(office.get('zipcode', ''))
  return ' '.join(address)

def office_hash(office):
  if not office.has_key('_source_hash'):
    raise Exception('office_hash() requires a valid office element as input (_source_hash key missing)')
  return office['_source_hash'] # deliberately meant to throw an error if key doesn't exist
  
def geocode(offices):
  """ Geocodes retrieved district office information, caching results 
  to pickle files. """

  # make geocoded result caching directory
  utils.mkdir_p('data/geocode')

  for bioguide in offices:    
    for office in offices[bioguide]:  

      # skip obviously incomplete or broken records  
      if type(office) is not dict:
        continue
      if not(office.has_key('address_0') and office.has_key('city') and office.has_key('state') and office.has_key('zipcode')):
        continue

      # skip previously geocoded offices
      ohash = office_hash(office)
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

def remove_dc(offices):
  output = {}
  removal_count = 0
  for bioguide in offices:
    for office in offices[bioguide]:
      if not office.get('state','').upper().replace('.', '').strip() in ('DC', 'DISTRICT OF COLUMBIA'):
        if not output.has_key(bioguide):
          output[bioguide] = []
        output[bioguide].append(office)
    else:
      removal_count = removal_count + 1
  
  print "Removed %d D.C. offices." % removal_count
  print "Saving..."
  save_data(output, "legislators-district-offices-unreviewed.yaml")
  return output

if __name__ == '__main__':

  if save_locked():
    os.unlink(LOCKFILE)  

  debug = utils.flags().get('debug', False)
  cache = utils.flags().get('cache', False)
  debug_bioguide = utils.flags().get('bioguide', None)

  offices = None

  if utils.flags().get('scrape', False):
    offices = scrape() # collect basic info

  if utils.flags().get('remove-dc', False):
    if offices is None:
      offices = utils.load_data("legislators-district-offices-unreviewed.yaml") # load data if necessary
    offices = remove_dc(offices) # remove DC offices

  if utils.flags().get('geocode', False):
    if offices is None:
      offices = utils.load_data("legislators-district-offices-unreviewed.yaml") # load data if necessary
    geocode(offices) # geocode data

  if utils.flags().get('verify', False):
    if offices is None:
      offices = utils.load_data("legislators-district-offices-unreviewed.yaml") # load data if necessary    
    offices = verify(offices) # test geocoded info against districts

  if utils.flags().get('review', False):
    if offices is None:
      offices = utils.load_data('legislators-district-offices-unreviewed.yaml')
      if len(offices)==0:
        print 'No reviewable data found.'
      else:
        review()



