#!/usr/bin/env python
#
# Google App Engine app for tracking Facebook defriends
#


import string
from random import choice
import cgi
import logging
import os.path
import time
import urllib
import urllib2
import wsgiref.handlers

from cookie_fns import set_cookie, parse_cookie, cookie_signature
from constants import FACEBOOK_APP_ID, FACEBOOK_APP_SECRET, MISSING_THRESHOLD, EMAIL_TEMPLATE

from django.utils import simplejson as json
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
from google.appengine.api.urlfetch import DownloadError
from google.appengine.api import mail


class User(db.Model):
    id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    name = db.StringProperty(required=True)
    access_token = db.StringProperty(required=True)
    friends = db.StringListProperty(required=True)
    email = db.EmailProperty(required=False)
    wants_email = db.BooleanProperty(required=False)
    tag = db.StringProperty(required=False)


# Keeps track of suspected people who've defriended, to compensate for 
# inconsistency in Facebook's API :(
class Suspect(db.Model):
    fb_id = db.StringProperty(required=True)
    fb_name = db.StringProperty(required=True)
    friend_id = db.StringProperty(required=True)
    missing_count = db.IntegerProperty(required=False, default=1)


# Notifications to ignore
class Ignore(db.Model):
    fb_id = db.StringProperty(required=True)
    friend_id = db.StringProperty(required=True)


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
        splits = []
        if self.current_user:
            # user is still logged in from a while ago
            updated = do_compare_on_interval(self.current_user)

            defriends = db.GqlQuery("SELECT * FROM Suspect WHERE friend_id='%s' AND missing_count > %d" 
                % (self.current_user.id, MISSING_THRESHOLD))

            for f in defriends:
                splits.append((f.fb_name, f.fb_id))
                f.delete()

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
            response = cgi.parse_qs(urllib2.urlopen(
                "https://graph.facebook.com/oauth/access_token?" +
                urllib.urlencode(args)).read())
            access_token = response["access_token"][-1]

            # TODO handle failure here:
            profile = json.load(urllib2.urlopen(
                "https://graph.facebook.com/me?" +
                urllib.urlencode(dict(access_token=access_token))))

            key = str(profile["id"])
            person = User.get_by_key_name(key)
            logging.debug(key + ' login')

            if person == None:
                # create new
                do_compare(profile=profile, access_token=access_token)
            else:
                # update old
                do_compare_on_interval(person)

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
            user.wants_email = False
            user.put()
            self.response.out.write('<html><head><meta http-equiv="refresh" content="2;url=http://facebook-monitor.appspot.com"></head><body>You will no longer receive emails from this app</body></html>')
        else:
            self.response.out.write('Invalid')


class YesEmailHandler(BaseHandler):
    def get(self):
        id = self.request.get('id', default_value='-1')
        tag = self.request.get('tag', default_value='')
        user = User.get_by_key_name(id)
        if user and user.tag == tag:
            user.wants_email = True
            user.put()
            self.response.out.write('<html><head><meta http-equiv="refresh" content="2;url=http://facebook-monitor.appspot.com"></head><body>You will now receive emails from this app</body></html>')
        else:
            self.response.out.write('Invalid')


class IgnoreHandler(BaseHandler):
    def get(self):
        id = self.request.get('id', default_value='-1')
        ignore = self.request.get('ignore', default_value='-1')
        tag = self.request.get('tag', default_value='')
        user = User.get_by_key_name(id)
        if user and user.tag == tag:
            ignore = Ignore(fb_id=id, friend_id=ignore)
            ignore.put()
            self.response.out.write('<html><head><meta http-equiv="refresh" content="2;url=http://facebook-monitor.appspot.com"></head><body>You will no longer receive notification for this person</body></html>')
        else:
            self.response.out.write('Invalid')


# Compares versions of friends list
# user is specified if the user is already logged in but a certain amount of
#   time has passed since the last refresh
# profile, access_token are specified if the user is logging in 
def do_compare(user=None, profile=None, access_token=None, force_complete_update=False):

    if not access_token:
        access_token = user.access_token
        
    # Load friends data
    try:
        friends_data = json.load(urllib2.urlopen(
            "https://graph.facebook.com/me/friends?" +
            urllib.urlencode(dict(access_token=access_token))))
    except:
        return False

    if not friends_data or "data" not in friends_data:
        return False

    friend_ids = [x["id"] for x in friends_data["data"]]

    # Update user info
    if user:
        # Compare
        logging.debug(user.id + ' running comparison!')
        d = {}
        readd = []
        for f in friend_ids:
            d[f] = True

        # Get list of possible defrienders we're already keeping track of
        possible_defriends = db.GqlQuery("SELECT * FROM Suspect WHERE friend_id='%s'" % (user.id))
        possible_defriend_ids = [x.fb_id for x in possible_defriends]
        logging.debug(user.id + ' retrieved ' + str(len(possible_defriend_ids)) + ' suspect records')

        # Get list of id to ignore
        ignore = db.GqlQuery("SELECT * FROM Ignore WHERE fb_id='%s'" % (user.id))
        ignore_ids = [x.friend_id for x in ignore]

        for f in user.friends:
            if f in ignore_ids:
                continue

            try:
                idx = possible_defriend_ids.index(f)
                logging.debug(user.id + ' recalling ' + f + ' is potential defriender')
            except ValueError:
                idx = -1

            if f in d:
                # In friends list - so remove any missing records
                if idx > -1:
                    logging.debug(user.id + ' deleting potential defriender that\'s been found')
                    possible_defriends[idx].delete()
            else:
                # Get person's name - missing from friends list
                # TODO memcache this
                loadme = "https://graph.facebook.com/%s?%s" \
                    % (f, urllib.urlencode(dict(access_token=access_token)))
                logging.debug(user.id + ' loading ' + loadme)

                try:
                    info = json.load(urllib2.urlopen(loadme))
                except DownloadError:
                    friend_ids.append(f)
                    continue

                if type(info) == bool:
                    # facebook failed, so skip and save for some future check
                    readd.append(f)
                    logging.warning(user.id + ' failed lookup on ' + loadme)
                elif "name" in info:
                    logging.debug(user.id + ' found missing ' + info["name"])

                    # record possible defriender
                    if idx > -1:
                        # already exists, so update count
                        logging.warning('%s Found missing friend %s, incrementing count' % (user.id, f))
                        s = possible_defriends[idx]
                        s.missing_count += 1
                    else:
                        # create new
                        logging.warning('%s Creating missing friend %s' % (user.id, f))
                        s = Suspect(key_name=f+':'+user.id,
                            fb_id=f,
                            fb_name=info['name'],
                            friend_id=user.id,
                            missing_count=1)

                    # keep it on the friends list for future comparisons, if necessary
                    if s.missing_count <= MISSING_THRESHOLD:
                        readd.append(f)
                    s.put()
                    
        if not force_complete_update:
            friend_ids.extend(readd)
        user.friends = friend_ids
    else:
        # Create new
        logging.debug(profile['id'] + 'bootstrapping')
        user = User(key_name=profile["id"], id=str(profile["id"]), \
            name=profile["name"], access_token=access_token, \
            friends=friend_ids, \
            email=profile["email"], \
            wants_email=True, \
            tag = ''.join([choice(string.letters + string.digits) for i in range(10)]), \
            )

    user.put()
    return True


# Runs comparison only if 15 minutes have passed
def do_compare_on_interval(user):
    timestamp = time.mktime(user.updated.timetuple())
    if time.time() - timestamp > 900:
        return do_compare(user)
    return False


# For forcing updates
class ResetHandler(BaseHandler):
    def get(self):
        id = self.request.get('id', default_value='-1')
        u = User.get_by_key_name(id)
        if u:
            do_compare(u, force_complete_update=True)
            self.response.out.write('ok')
        else:
            self.response.out.write('invalid')


class TestHandler(BaseHandler):
    def get(self):
        id = self.request.get('id', default_value='-1')
        u = User.get_by_key_name(id)
        if u:
            do_compare(u)
            self.response.out.write('ok')
        else:
            self.response.out.write('invalid')


# Emails people who need to be notified
class MailerHandler(webapp.RequestHandler):
    def get(self):
        mailer_update_all()
        self.response.out.write('Done mailing')


# Runs comparisons and mails out as necessary
def mailer_update_all():
    logging.info('mailing all')

    us = db.GqlQuery("SELECT * FROM User")
    for u in us:
        logging.info(u.id + ' returned in query')
        if u.friends:
            # User is in system, so update and compare
            if not do_compare(u):
                logging.warning(u.id + ' update failed, skipping')
                continue

            if not u.wants_email:
                continue

            # look up potential defriends for user
            defriends = db.GqlQuery("SELECT * FROM Suspect WHERE friend_id='%s' AND missing_count > %d"
                % (u.id, MISSING_THRESHOLD))
            if defriends.count() > 0:
                # Missing friends! Send email
                logging.info(u.id + ' SENDING MAIL')

                missing_names = []
                ignore_links = []
                for s in defriends:
                    missing_names.append(s.fb_name)
                    ignore_links.append('http://facebook-monitor.appspot.com/ignore?id=%s&tag=%s&ignore=%s - %s' % (u.id, u.tag, s.fb_id, s.fb_name))
                    s.delete()

                noemail_link = 'http://facebook-monitor.appspot.com/noemail?id=%s&tag=%s' % (u.id, u.tag)
                cancel_link = 'http://facebook-monitor.appspot.com/cancel?id=%s&tag=%s' % (u.id, u.tag)

                mail.send_mail(
                    sender='Friend Monitor <friend.monitor.noreply@facebook-monitor.appspotmail.com>',
                    to=u.email,
                    subject='Facebook Friend Monitor Notification',
                    body= EMAIL_TEMPLATE % (u.name, '\n'.join(missing_names), '\n'.join(ignore_links), noemail_link, cancel_link,))


def main():
    util.run_wsgi_app(webapp.WSGIApplication([
        (r"/", HomeHandler),
        (r"/noemail", NoEmailHandler),
        (r"/yesemail", YesEmailHandler),
        (r"/ignore", IgnoreHandler),
        (r"/cancel", CancelHandler),
        (r"/cron", MailerHandler),
        (r"/reset", ResetHandler),
        (r"/test", TestHandler),
        (r"/auth/login", LoginHandler),
        (r"/auth/logout", LogoutHandler),
    ]))


if __name__ == "__main__":
    main()
