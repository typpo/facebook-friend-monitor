# Activate for local testing/deployment
DEBUG = False

if DEBUG:
    FACEBOOK_APP_ID = '183916088320307'
    FACEBOOK_APP_SECRET = '54eacbbd8cb433b68a67282f8d83fb0a'
else:
    FACEBOOK_APP_ID = "172469002787534"
    FACEBOOK_APP_SECRET = "5e4f10d636ea301cd232df4a758c4fd5"

# Number of times a friend doesn't appear in friends list to be deemed missing
MISSING_THRESHOLD = 10

# Defriend email template
EMAIL_TEMPLATE="""Hi %s,

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
"""
