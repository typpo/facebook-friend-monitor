#!/usr/bin/env python
#
#
#


import string
from random import choice
import cgi
import logging
import os.path
import time
import urllib
import wsgiref.handlers

from cookie_fns import set_cookie, parse_cookie, cookie_signature
from constants import FACEBOOK_APP_ID, FACEBOOK_APP_SECRET, MISSING_THRESHOLD

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
            # user is still logged in from a while ago
            updated = do_compare_on_interval(self.current_user)

        splits = []
        if self.current_user:
            defriends = db.GqlQuery("SELECT * FROM Suspect WHERE friend_id='%s' AND missing_count > %d" 
                % (self.current_user.id, MISSING_THRESHOLD))

            for f in defriends:
                splits.append((f.fb_name, f.fb_id))

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
        logging.debug(user.id + ' running comparison')
        d = {}
        failed = []
        for f in friend_ids:
            d[f] = True

        for f in user.friends:
            if f not in d or f == '100000866256332':
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

                    # record suspected defriender
                    s = Suspect.get_by_key_name(f+':'+user.id)
                    if s:
                        # already exists, so update count
                        logging.warning('%s Found missing friend %s, incrementing count' % (user.id, f))
                        s.missing_count += 1
                    else:
                        # create new
                        logging.warning('%s Creating missing friend %s' % (user.id, f))
                        s = Suspect(key_name=f+':'+user.id,
                            fb_id=f,
                            fb_name=info['name'],
                            friend_id=user.id,
                            missing_count=1)
                    s.put()
                    
        friend_ids.extend(failed)
        user.friends = friend_ids
    else:
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


# Runs comparison only if 10 minutes have passed
def do_compare_on_interval(user):
    timestamp = time.mktime(user.updated.timetuple())
    if time.time() - timestamp > 600:
        return do_compare(user)
    return False


# Emails people who need to be notified
class MailerHandler(webapp.RequestHandler):
    def get(self):
        mailer_update_all()
        self.response.out.write('Done mailing')


def mailer_update_all():
    logging.info('mailing all')

    us = db.GqlQuery("SELECT * FROM User WHERE wants_email=True")
    for u in us:
        logging.info(u.id + ' returned in query')
        if u.friends:
            # User is in system, so update and compare
            do_compare(u)

            # look up potential defriends for user
            defriends = db.GqlQuery("SELECT * FROM Suspect WHERE friend_id='%s' AND missing_count > %d"
                % (u.id, MISSING_THRESHOLD))
            if defriends.count() > 0:
                # Missing friends! Send email
                logging.info(u.id + ' mailing')

                missing_names = []
                for s in defriends:
                    missing_names.append(s.fb_name)
                    s.delete()

                noemail_link = 'http://facebook-monitor.appspot.com/noemail?id=%s&tag=%s' % (u.id, u.tag)
                cancel_link = 'http://facebook-monitor.appspot.com/cancel?id=%s&tag=%s' % (u.id, u.tag)

                mail.send_mail(
                    sender='Friend Monitor <friend.monitor.noreply@facebook-monitor.appspotmail.com>',
                    to=u.email,
                    subject='Facebook Friend Monitor Notification',
                    body="""Hi %s,

These friends no longer show up on your friends list:

%s

-----------------------------
People can go missing from your friends list if they've defriended you, or you've defriended them - there's no way to tell the difference.  And occasionally Facebook's API might not return full information, which can lead to false positives.

You got this email because you're subscribed to Facebook Friend Monitor @ http://facebook-monitor.appspot.com

To not get emails anymore, go here (you can still see who's defriending you by going to our website):
%s

To fully cancel your account, go here:
%s

Regards,
The Monitor
                    """ % (u.name, '\n'.join(missing_names), noemail_link, cancel_link))


def main():
    util.run_wsgi_app(webapp.WSGIApplication([
        (r"/", HomeHandler),
        (r"/noemail", NoEmailHandler),
        (r"/yesemail", YesEmailHandler),
        (r"/cancel", CancelHandler),
        (r"/cron", MailerHandler),
        (r"/auth/login", LoginHandler),
        (r"/auth/logout", LogoutHandler),
    ]))


if __name__ == "__main__":
    main()
