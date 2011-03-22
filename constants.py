# Activate for local deployment
DEBUG = False

if DEBUG:
    FACEBOOK_APP_ID = '183916088320307'
    FACEBOOK_APP_SECRET = '54eacbbd8cb433b68a67282f8d83fb0a'
else:
    FACEBOOK_APP_ID = "172469002787534"
    FACEBOOK_APP_SECRET = "5e4f10d636ea301cd232df4a758c4fd5"

# Number of times a friend doesn't appear in friends list to be deemed missing
MISSING_THRESHOLD = 5
