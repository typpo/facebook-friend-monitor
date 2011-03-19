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

# Activate for local deployment
DEBUG = True

if DEBUG:
    FACEBOOK_APP_ID = '183916088320307'
    FACEBOOK_APP_SECRET = '54eacbbd8cb433b68a67282f8d83fb0a'
else:
    FACEBOOK_APP_ID = "172469002787534"
    FACEBOOK_APP_SECRET = "5e4f10d636ea301cd232df4a758c4fd5"

import string
from random import choice
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
    access_token = db.StringProperty(required=True)
    friends = db.StringListProperty(required=True)
    missing = db.StringListProperty(required=True)
    email = db.EmailProperty(required=False)
    wants_email = db.BooleanProperty(required=False)
    tag = db.StringProperty(required=False)


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
            # Check only once every 5 minutes
            timestamp = time.mktime(self.current_user.updated.timetuple())
            if time.time() - timestamp > 300:
                if do_compare(self.current_user):
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
        args = dict(client_id=FACEBOOK_APP_ID, redirect_uri=self.request.path_url, scope="email,offline_access")
        if self.request.get("code"):
            args["client_secret"] = FACEBOOK_APP_SECRET
            args["code"] = self.request.get("code")
            response = cgi.parse_qs(urllib.urlopen(
                "https://graph.facebook.com/oauth/access_token?" +
                urllib.urlencode(args)).read())
            access_token = response["access_token"][-1]

            # Download the user profile and cache a local instance of the
            # basic profile info
            # TODO handle failure
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


class CancelHandler(BaseHandler):
    def get(self):
        id = self.request.get('id', default_value='-1')
        tag = self.request.get('tag', default_value='')
        user = User.get_by_key_name(id)
        if user and user.tag == tag:
            user.delete()
            self.response.out.write('<html><head><meta http-equiv="refresh" content="2;url=http://facebook-monitor.appspot.com"></head><body>Your data has been wiped from this app</body></html>')
        else:
            self.response.out.write('Invalid')


class NoEmailHandler(BaseHandler):
    def get(self):
        id = self.request.get('id', default_value='-1')
        tag = self.request.get('tag', default_value='')
        user = User.get_by_key_name(id)
        if user and user.tag == tag:
            self.current_user.wants_email = False
            self.current_user.put()
            self.response.out.write('<html><head><meta http-equiv="refresh" content="2;url=http://facebook-monitor.appspot.com"></head><body>You will no longer receive emails from this app</body></html>')
        else:
            self.response.out.write('Invalid')


class YesEmailHandler(BaseHandler):
    def get(self):
        id = self.request.get('id', default_value='-1')
        tag = self.request.get('tag', default_value='')
        user = User.get_by_key_name(id)
        if user and user.tag == tag:
            self.current_user.wants_email = True
            self.current_user.put()
            self.response.out.write('<html><head><meta http-equiv="refresh" content="2;url=http://facebook-monitor.appspot.com"></head><body>You will now receive emails from this app</body></html>')
        else:
            self.response.out.write('Invalid')


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
        return False

    if not friends_data or "data" not in friends_data:
        return False

    friend_ids = [x["id"] for x in friends_data["data"]]

    # Update user info
    if user:
        # Compare
        logging.debug('running comparison')
        d = {}
        missing = []
        failed = []
        for f in friend_ids:
            d[f] = True
        for f in user.friends:
            if f not in d:
                # Get person's name - missing from friends list
                loadme = "https://graph.facebook.com/%s?%s" \
                    % (f, urllib.urlencode(dict(access_token=access_token)))
                logging.debug(user.id + ' loading ' + loadme)
                info = json.load(urllib.urlopen(loadme))
                if type(info) == bool:
                    # facebook failed, so skip and save for some future check
                    failed.append(f)
                    logging.warning(user.id + ' failed lookup on ' + loadme)
                elif "name" in info:
                    logging.debug(user.id + ' found missing ' + info["name"])
                    missing.append(info["name"] + ':' + f)

        friend_ids.extend(failed)

        user.missing = missing
        user.friends = friend_ids
    else:
        logging.debug('bootstrapping')
        user = User(key_name=profile["id"], id=str(profile["id"]), \
            name=profile["name"], access_token=access_token, \
            friends=friend_ids, \
            missing=[], \
            email=profile["email"], \
            wants_email=True, \
            tag = ''.join([choice(string.letters + string.digits) for i in range(10)]), \
            )

    user.put()
    return True


# Emails people who need to be notified
class MailerHandler(webapp.RequestHandler):
    def get(self):
        mailer_update_all()
        self.response.out.write('Invalid')


def mailer_update_all():
    from google.appengine.api import mail

    users = db.GqlQuery("SELECT * FROM User WHERE email!='' AND wants_email=True")
    for user in users:
        if user.friends:
            # User is in system, so update and compare
            do_compare(user)
            if user.missing:
                # Missing friends! Send email
                logging.debug(user.id + ' mailing')

                missing_names = []
                for s in user.missing:
                    tmp = s.split(':')
                    if len(tmp) == 2:
                        missing_names.append(tmp[0])

                noemail_link = 'http://facebook-monitor.appspot.com/noemail?id=%s&tag=%s' % (user.id, user.tag)
                cancel_link = 'http://facebook-monitor.appspot.com/cancel?id=%s&tag=%s' % (user.id, user.tag)

                mail.send_mail(
                    sender='Friend Monitor <facebook-friend-monitor-noreply@ianww.com',
                    to=user.email,
                    subject='Facebook Friend Monitor Notification',
                    body="""
                    Hi %s,

                    These friends no longer show up on your friends list:
                    %s

                    People can go missing from your friends list for a couple of reasons:
                        1. They've deactivated their Facebook accounts
                        2.  Facebook's API isn't providing the complete list (this happens)
                        3.  They've DEFRIENDED you (or you've defriended them)

                    You got this email because you're subscribed to Facebook Friend Monitor @ http://facebook-monitor.appspot.com

                    To not get emails anymore, go here (you can still see who's defriending you by going to our website):
                    %s

                    To fully cancel your account, go here:
                    %s

                    Regards,
                    The Monitor
                    """ % (user.name, '\n\t'.join(missing_names), noemail_link, cancel_linnk))


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
        (r"/noemail", NoEmailHandler),
        (r"/yesemail", YesEmailHandler),
        (r"/cancel", CancelHandler),
        (r"/crab_magnet", MailerHandler),
        (r"/auth/login", LoginHandler),
        (r"/auth/logout", LogoutHandler),
    ]))


if __name__ == "__main__":
    main()
