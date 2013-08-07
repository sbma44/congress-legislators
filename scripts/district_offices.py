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

def main():
  regexes = {
    "youtube": [
      "https?://(?:www\\.)?youtube.com/channel/([^\\s\"/\\?#']+)",
      "https?://(?:www\\.)?youtube.com/(?:subscribe_widget\\?p=)?(?:subscription_center\\?add_user=)?(?:user/)?([^\\s\"/\\?#']+)"
    ],
    "facebook": [
      "\\('facebook.com/([^']+)'\\)",
      "https?://(?:www\\.)?facebook.com/(?:home\\.php)?(?:business/dashboard/#/)?(?:government)?(?:#!/)?(?:#%21/)?(?:#/)?pages/[^/]+/(\\d+)",
      "https?://(?:www\\.)?facebook.com/(?:profile.php\\?id=)?(?:home\\.php)?(?:#!)?/?(?:people)?/?([^/\\s\"#\\?&']+)"
    ],
    "twitter": [
      "https?://(?:www\\.)?twitter.com/(?:intent/user\?screen_name=)?(?:#!/)?(?:#%21/)?@?([^\\s\"'/]+)",
      "\\.render\\(\\)\\.setUser\\('@?(.*?)'\\)\\.start\\(\\)"
    ]
  }

  email_enabled = utils.flags().get('email', False)
  debug = utils.flags().get('debug', False)
  do_update = utils.flags().get('update', False)
  do_clean = utils.flags().get('clean', False)
  do_verify = utils.flags().get('verify', False)
  do_resolvefb = utils.flags().get('resolvefb', False)
  do_resolveyt = utils.flags().get('resolveyt', False)

  # default to not caching
  cache = utils.flags().get('cache', False)
  force = not cache

  if do_resolvefb:
    service = "facebook"
  elif do_resolveyt:
    service = "youtube"
  else:
    service = utils.flags().get('service', None)
  if service not in ["twitter", "youtube", "facebook"]:
    print "--service must be one of twitter, youtube, or facebook"
    exit(0)

  # load in members, orient by bioguide ID
  print "Loading current legislators..."
  current = load_data("legislators-current.yaml")

  current_bioguide = { }
  for m in current:
    if m["id"].has_key("bioguide"):
      current_bioguide[m["id"]["bioguide"]] = m

  print "Loading blacklist..."
  blacklist = {
    'twitter': [], 'facebook': [], 'youtube': []
  }
  for rec in csv.DictReader(open("data/social_media_blacklist.csv")):
    blacklist[rec["service"]].append(rec["pattern"])

  print "Loading whitelist..."
  whitelist = {
    'twitter': [], 'facebook': [], 'youtube': []
  }
  for rec in csv.DictReader(open("data/social_media_whitelist.csv")):
    whitelist[rec["service"]].append(rec["account"].lower())

  # reorient currently known social media by ID
  print "Loading social media..."
  media = load_data("legislators-social-media.yaml")
  media_bioguide = { }
  for m in media:
    media_bioguide[m["id"]["bioguide"]] = m


  def resolvefb():
    updated_media = []
    for m in media:
      social = m['social']

      if ('facebook' in social and social['facebook']) and ('facebook_id' not in social):
        graph_url = "https://graph.facebook.com/%s" % social['facebook']

        if re.match('\d+', social['facebook']):
          social['facebook_id'] = social['facebook']
          print "Looking up graph username for %s" % social['facebook']
          fbobj = requests.get(graph_url).json()
          if 'username' in fbobj:
            print "\tGot graph username of %s" % fbobj['username']
            social['facebook'] = fbobj['username']
          else:
            print "\tUnable to get graph username"

        else:
          try:
            print "Looking up graph ID for %s" % social['facebook']
            fbobj = requests.get(graph_url).json()
            if 'id' in fbobj:
              print "\tGot graph ID of %s" % fbobj['id']
              social['facebook_id'] = fbobj['id']
            else:
              print "\tUnable to get graph ID"
          except:
            print "\tUnable to get graph ID for: %s" % social['facebook']
            social['facebook_id'] = None

      updated_media.append(m)

    print "Saving social media..."
    save_data(updated_media, "legislators-social-media.yaml")


  def resolveyt():
    # To avoid hitting quota limits, register for a YouTube 2.0 API key at
    # https://code.google.com/apis/youtube/dashboard
    # and put it below
    api_file = open('cache/youtube_api_key','r')
    api_key = api_file.read()

    bioguide = utils.flags().get('bioguide', None)

    updated_media = []
    for m in media:
      if bioguide and (m['id']['bioguide'] != bioguide):
        updated_media.append(m)
        continue

      social = m['social']

      if ('youtube' in social) or ('youtube_id' in social):

        if 'youtube' not in social:
          social['youtube'] = social['youtube_id']

        ytid = social['youtube']

        profile_url = ("http://gdata.youtube.com/feeds/api/users/%s"
        "?v=2&prettyprint=true&alt=json&key=%s" % (ytid, api_key))

        try:
          print "Resolving YT info for %s" % social['youtube']
          ytreq = requests.get(profile_url)
          # print "\tFetched with status code %i..." % ytreq.status_code

          if ytreq.status_code == 404:
            # If the account name isn't valid, it's probably a redirect.
            try:
              # Try to scrape the real YouTube username
              print "\Scraping YouTube username"
              search_url = ("http://www.youtube.com/%s" % social['youtube'])
              csearch = requests.get(search_url).text.encode('ascii','ignore')

              u = re.search(r'<a[^>]*href="[^"]*/user/([^/"]*)"[.]*>',csearch)

              if u:
                print "\t%s maps to %s" % (social['youtube'],u.group(1))
                social['youtube'] = u.group(1)
                profile_url = ("http://gdata.youtube.com/feeds/api/users/%s"
                "?v=2&prettyprint=true&alt=json" % social['youtube'])

                print "\tFetching GData profile..."
                ytreq = requests.get(profile_url)
                print "\tFetched GData profile"

              else:
                raise Exception("Couldn't figure out the username format for %s" % social['youtube'])

            except:
              print "\tCouldn't locate YouTube account"
              raise

          ytobj = ytreq.json()
          social['youtube_id'] = ytobj['entry']['yt$channelId']['$t']
          # print "\tResolved youtube_id to %s" % social['youtube_id']

          # even though we have their channel ID, do they also have a username?
          if ytobj['entry']['yt$username']['$t'] != ytobj['entry']['yt$userId']['$t']:
            if social['youtube'].lower() != ytobj['entry']['yt$username']['$t'].lower():
              old_name = social['youtube']
              # YT accounts are case-insensitive.  Preserve capitalization if possible.
              social['youtube'] = ytobj['entry']['yt$username']['$t']
              print "\tAdded YouTube username of %s" % social['youtube']
          else:
            print "\tYouTube says they do not have a separate username"
            del social['youtube']
        except:
          print "Unable to get YouTube Channel ID for: %s" % social['youtube']

      updated_media.append(m)

    print "Saving social media..."
    save_data(updated_media, "legislators-social-media.yaml")


  def sweep():
    to_check = []

    bioguide = utils.flags().get('bioguide', None)
    if bioguide:
      possibles = [bioguide]
    else:
      possibles = current_bioguide.keys()

    for bioguide in possibles:
      if media_bioguide.get(bioguide, None) is None:
        to_check.append(bioguide)
      elif (media_bioguide[bioguide]["social"].get(service, None) is None) and \
        (media_bioguide[bioguide]["social"].get(service + "_id", None) is None):
        to_check.append(bioguide)
      else:
        pass

    utils.mkdir_p("cache/social_media")
    writer = csv.writer(open("cache/social_media/%s_candidates.csv" % service, 'w'))
    writer.writerow(["bioguide", "official_full", "website", "service", "candidate", "candidate_url"])

    if len(to_check) > 0:
      rows_found = []
      for bioguide in to_check:
        candidate = candidate_for(bioguide)
        if candidate:
          url = current_bioguide[bioguide]["terms"][-1].get("url", None)
          candidate_url = "https://%s.com/%s" % (service, candidate)
          row = [bioguide, current_bioguide[bioguide]['name']['official_full'].encode('utf-8'), url, service, candidate, candidate_url]
          writer.writerow(row)
          print "\tWrote: %s" % candidate
          rows_found.append(row)

      if email_enabled and len(rows_found) > 0:
        email_body = "Social media leads found:\n\n"
        for row in rows_found:
          email_body += ("%s\n" % row)
        utils.send_email(email_body)

  def verify():
    bioguide = utils.flags().get('bioguide', None)
    if bioguide:
      to_check = [bioguide]
    else:
      to_check = media_bioguide.keys()

    for bioguide in to_check:
      entry = media_bioguide[bioguide]
      current = entry['social'].get(service, None)
      if not current:
        continue

      bioguide = entry['id']['bioguide']

      candidate = candidate_for(bioguide)
      if not candidate:
        # if current is in whitelist, and none is on the page, that's okay
        if current.lower() in whitelist[service]:
          continue
        else:
          candidate = ""

      url = current_bioguide[bioguide]['terms'][-1].get('url')

      if current.lower() != candidate.lower():
        print "[%s] mismatch on %s - %s -> %s" % (bioguide, url, current, candidate)

  def update():
    for rec in csv.DictReader(open("cache/social_media/%s_candidates.csv" % service)):
      bioguide = rec["bioguide"]
      candidate = rec["candidate"]

      if media_bioguide.has_key(bioguide):
        media_bioguide[bioguide]['social'][service] = candidate
      else:
        new_media = {'id': {}, 'social': {}}

        new_media['id']['bioguide'] = bioguide
        thomas_id = current_bioguide[bioguide]['id'].get("thomas", None)
        govtrack_id = current_bioguide[bioguide]['id'].get("govtrack", None)
        if thomas_id:
          new_media['id']['thomas'] = thomas_id
        if govtrack_id:
          new_media['id']['govtrack'] = govtrack_id


        new_media['social'][service] = candidate
        media.append(new_media)

    print "Saving social media..."
    save_data(media, "legislators-social-media.yaml")

    # if it's a youtube update, always do the resolve
    if service == "youtube":
      resolveyt()


  def clean():
    print "Loading historical legislators..."
    historical = load_data("legislators-historical.yaml")

    count = 0
    for m in historical:
      if media_bioguide.has_key(m["id"]["bioguide"]):
        media.remove(media_bioguide[m["id"]["bioguide"]])
        count += 1
    print "Removed %i out of office legislators from social media file..." % count

    print "Saving historical legislators..."
    save_data(media, "legislators-social-media.yaml")

  def candidate_for(bioguide):
    url = current_bioguide[bioguide]["terms"][-1].get("url", None)
    if not url:
      if debug:
        print "[%s] No official website, skipping" % bioguide
      return None

    if debug:
      print "[%s] Downloading..." % bioguide
    cache = "congress/%s.html" % bioguide
    body = utils.download(url, cache, force, {'check_redirects': True})

    all_matches = []
    for regex in regexes[service]:
      matches = re.findall(regex, body, re.I)
      if matches:
        all_matches.extend(matches)

    if all_matches:
      for candidate in all_matches:
        passed = True
        for blacked in blacklist[service]:
          if re.search(blacked, candidate, re.I):
            passed = False

        if not passed:
          if debug:
            print "\tBlacklisted: %s" % candidate
          continue

        return candidate
      return None

  if do_update:
    update()
  elif do_clean:
    clean()
  elif do_verify:
    verify()
  elif do_resolvefb:
    resolvefb()
  elif do_resolveyt:
    resolveyt()
  else:
    sweep()


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


def main():
  debug = utils.flags().get('debug', False)
  cache = utils.flags().get('cache', False)
  force = not cache


  # load in members, orient by bioguide ID
  print "Loading current legislators..."
  current = load_data("legislators-current.yaml")

  current_bioguide = { }
  for m in current:
    if m["id"].has_key("bioguide"):
      current_bioguide[m["id"]["bioguide"]] = m

  output = {}

  for bioguide in current_bioguide.keys():
    url = current_bioguide[bioguide]["terms"][-1].get("url", None)
    state = current_bioguide[bioguide]["terms"][-1].get("state", 'XX')
    if not url:
      if debug:
        print "[%s] No official website, skipping" % bioguide
      return None

    if debug:
      print "[%s] Downloading..." % bioguide
    cache = "congress/%s.html" % bioguide
    body = utils.download(url, cache, force, {'check_redirects': True})
    
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

      state_present = re.search(r'\W%s\W' % state.upper(), element_text.upper())
      if possible_zipcode_matches:
        if len(possible_zipcode_matches)==1 and possible_phone_matches and state_present:          
          # check to ensure we haven't already added this element -- use zip and phone as keys
          key = "%s/%s" % (''.join(possible_zipcode_matches[0]).strip(), re.sub(r'[^\d]','',possible_phone_matches.group(0).strip()))          
          possible_office_matches[key] = element
      
    # process each (hopefully!) distinct match
    for (key,match) in possible_office_matches.items():  

      extracted_info = {}      
 
      # remove wrapping tag
      match_html = re.sub(r'<\s*%s[^>]*>(.*?)<\s*\/%s.*?>' % (match.tag, match.tag),r'\1', lxml.etree.tostring(match), flags=(re.DOTALL|re.MULTILINE|re.IGNORECASE))
      # remove other junk
      match_html = re.sub('&nbsp;',' ', re.sub(r'&#13;','',match_html)).strip()
      # turn a close/open div pair into a <br/> -- hacky!
      match_html = re.sub(r'<\/div>', '\n', match_html, (re.MULTILINE|re.IGNORECASE|re.DOTALL))
      # break into lines & strip
      match_lines = map(lambda x: x.strip(), re.split(r'\n+', re.sub(r'<\s*br[^>]*>', '\n', match_html)))

      # now whittle away at the edges...
      
      # first: sanity check
      if len(match_lines)==0:
        continue

      # is the first line a label?
      if re.search(r'(<h\d|<strong|office:?)', match_lines[0], flags=re.I):
        extracted_info['label'] = re.sub(r'\:\s*$','',strip_tags(match_lines.pop(0)))
        if len(match_lines)==0:
          continue

      # is the last line a map link?
      if re.search(r'maps.google.com', match_lines[-1]):
        extracted_info['map_link'] = match_lines.pop()
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
          extracted_info['zipcode'] = re.sub(r'^>','',zipcode_match.group(0).strip())
          extracted_info['city'] = strip_tags(re.sub(r',\s*%s' % state,'',match_lines[i].replace(extracted_info['zipcode'],''), flags=re.IGNORECASE))
          extracted_info['state'] = state # assume all district offices are in-state
        elif found_zip:
          if len(strip_tags(match_lines[i]))>0:
            address_lines.insert(0, match_lines[i])                

      for (i,al) in enumerate(address_lines):
        extracted_info['address_%d' % i] = strip_tags(al)

      extracted_info['scraped'] = True
      extracted_info['scraped_date'] = datetime.datetime.now().isoformat()

      if not output.has_key(bioguide):
        output[bioguide] = []
      output[bioguide].append(extracted_info.copy())

    # print output.get(bioguide, "No offices found for %s" % bioguide)

  print "Saving data..."
  save_data(output, "legislators-district-offices.yaml")

  print "Found offices for %d members of %d" % (len(output.keys()), len(current_bioguide.keys()))
        

if __name__ == '__main__':
  main()

