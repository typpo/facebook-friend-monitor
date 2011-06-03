# Activate for local testing/deployment
DEBUG = False

# Number of times a friend doesn't appear in friends list to be deemed missing
MISSING_THRESHOLD = 10

# Defriend email template
EMAIL_TEMPLATE="""Hi %s,

These people no longer show up on your friends list:

%s

-----------------------------
People can go missing from your friends list if they've defriended you, or you've defriended them - there's no way to tell the difference.  And occasionally Facebook's API might not return full information, which can lead to false positives.

You got this email because you're subscribed to Facebook Friend Monitor.

If one of these notifications was incorrect, you can suppress it:
%s

To not get emails anymore, go here (you can still see who's defriending you by going to the website):
%s

To fully cancel your account, go here:
%s

Regards,
The Monitor
http://facebook-monitor.appspot.com
"""
