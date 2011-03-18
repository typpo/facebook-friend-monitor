#!/usr/bin/env python
#
# Copyright 2010 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

FACEBOOK_APP_ID = "172469002787534"
FACEBOOK_APP_SECRET = "5e4f10d636ea301cd232df4a758c4fd5"

import base64
import cgi
import Cookie
import email.utils
import hashlib
import hmac
import logging
import os.path
import time
import urllib
import wsgiref.handlers

from django.utils import simplejson as json
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
from google.appengine.api.urlfetch import DownloadError


class User(db.Model):
    id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    name = db.StringProperty(required=True)
    profile_url = db.StringProperty(required=True)
    access_token = db.StringProperty(required=True)
    friends = db.StringListProperty(required=True)
    missing = db.StringListProperty(required=True)


class BaseHandler(webapp.RequestHandler):
    @property
    def current_user(self):
        """Returns the logged in Facebook user, or None if unconnected."""
        if not hasattr(self, "_current_user"):
            self._current_user = None
            user_id = parse_cookie(self.request.cookies.get("fb_user"))
            if user_id:
                self._current_user = User.get_by_key_name(user_id)
        return self._current_user


class HomeHandler(BaseHandler):
    def get(self):
        updated = False
        if self.current_user:
            # check if user is still logged in from a while ago
            # Check only once every 15 minutes
            timestamp = time.mktime(self.current_user.updated.timetuple())
            if time.time() - timestamp > 900:
                do_compare(self.current_user)
                updated = True

        splits = []
        if self.current_user and self.current_user.missing:
            for s in self.current_user.missing:
                tmp = s.split(':')
                if len(tmp) == 2:
                    splits.append(tmp)


        path = os.path.join(os.path.dirname(__file__), "oauth.html")
        args = dict(current_user=self.current_user, updated=updated, splits=splits)
        self.response.out.write(template.render(path, args))


class LoginHandler(BaseHandler):
    def get(self):
        verification_code = self.request.get("code")
        args = dict(client_id=FACEBOOK_APP_ID, redirect_uri=self.request.path_url, scope="offline_access")
        if self.request.get("code"):
            args["client_secret"] = FACEBOOK_APP_SECRET
            args["code"] = self.request.get("code")
            response = cgi.parse_qs(urllib.urlopen(
                "https://graph.facebook.com/oauth/access_token?" +
                urllib.urlencode(args)).read())
            access_token = response["access_token"][-1]

            # Download the user profile and cache a local instance of the
            # basic profile info
            profile = json.load(urllib.urlopen(
                "https://graph.facebook.com/me?" +
                urllib.urlencode(dict(access_token=access_token))))

            key = str(profile["id"])
            person = User.get_by_key_name(key)
            logging.debug(key + ' login')
            missing = None

            if person == None:
                # create new
                do_compare(profile=profile, access_token=access_token)
            else:
                # update old
                do_compare(person)

            set_cookie(self.response, "fb_user", str(profile["id"]),
                       expires=time.time() + 30 * 86400)
            self.redirect("/")
        else:
            self.redirect(
                "https://graph.facebook.com/oauth/authorize?" +
                urllib.urlencode(args))


class LogoutHandler(BaseHandler):
    def get(self):
        set_cookie(self.response, "fb_user", "", expires=time.time() - 86400)
        self.redirect("/")

# Compares versions of friends list
# user is specified if the user is already logged in but a certain amount of
#   time has passed since the last refresh
# profile, access_token are specified if the user is logging in 
def do_compare(user=None, profile=None, access_token=None):

    if not access_token:
        access_token = user.access_token
        
    # Load friends data
    try:
        friends_data = json.load(urllib.urlopen(
            "https://graph.facebook.com/me/friends?" +
            urllib.urlencode(dict(access_token=access_token))))
    except DownloadError:
        return

    friend_ids = [x["id"] for x in friends_data["data"]]

    # Update user info
    if user:
        # Compare
        logging.debug('running comparison')
        d = {}
        missing = []
        for f in friend_ids:
            d[f] = True
        for f in user.friends:
            if f not in d or f == '100000866256332':
                # Get person's name - missing from friends list
                loadme = "https://graph.facebook.com/%s?%s" \
                    % (f, urllib.urlencode(dict(access_token=access_token)))
                logging.debug(user.id + ' loading ' + loadme)
                info = json.load(urllib.urlopen(loadme))
                if "name" in info:
                    logging.debug(user.id + ' found missing ' + info["name"])
                    missing.append(info["name"] + ':' + f)

        user = User(key_name=user.id, id=user.id, \
            name=user.name, access_token=access_token, \
            profile_url=user.profile_url, \
            friends=friend_ids, \
            missing=missing)
    else:
        logging.debug('bootstrapping')
        user = User(key_name=profile["id"], id=str(profile["id"]), \
            name=profile["name"], access_token=access_token, \
            profile_url=profile["link"], \
            friends=friend_ids, \
            missing=[])

    user.put()

def set_cookie(response, name, value, domain=None, path="/", expires=None):
    """Generates and signs a cookie for the give name/value"""
    timestamp = str(int(time.time()))
    value = base64.b64encode(value)
    signature = cookie_signature(value, timestamp)
    cookie = Cookie.BaseCookie()
    cookie[name] = "|".join([value, timestamp, signature])
    cookie[name]["path"] = path
    if domain: cookie[name]["domain"] = domain
    if expires:
        cookie[name]["expires"] = email.utils.formatdate(
            expires, localtime=False, usegmt=True)
    response.headers._headers.append(("Set-Cookie", cookie.output()[12:]))


def parse_cookie(value):
    """Parses and verifies a cookie value from set_cookie"""
    if not value: return None
    parts = value.split("|")
    if len(parts) != 3: return None
    if cookie_signature(parts[0], parts[1]) != parts[2]:
        logging.warning("Invalid cookie signature %r", value)
        return None
    timestamp = int(parts[1])
    if timestamp < time.time() - 30 * 86400:
        logging.warning("Expired cookie %r", value)
        return None
    try:
        return base64.b64decode(parts[0]).strip()
    except:
        return None


def cookie_signature(*parts):
    """Generates a cookie signature.

    We use the Facebook app secret since it is different for every app (so
    people using this example don't accidentally all use the same secret).
    """
    hash = hmac.new(FACEBOOK_APP_SECRET, digestmod=hashlib.sha1)
    for part in parts: hash.update(part)
    return hash.hexdigest()


def main():
    util.run_wsgi_app(webapp.WSGIApplication([
        (r"/", HomeHandler),
        (r"/auth/login", LoginHandler),
        (r"/auth/logout", LogoutHandler),
    ]))


if __name__ == "__main__":
    main()
