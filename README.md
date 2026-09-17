# OpenProtozoa
## NOTE: PROTOZOA HAS BEEN PATCHED.
Open source Protozoa exploit for Securly. <br>
Full credit to Bypassi and akabutnice for this exploit. Credit to me for writing the guide.

# Usage Instructions
1. Navigate to your Protozoa mirror (or https://protozoa.org)
2. Click the corresponding button
3. Follow the instructions on the site
4. Boom Securly should be disabled

# Hosting Instructions
Hosting your own mirror of Protozoa is a bit more complicated, and is not recommended unless you have no other way of using the exploit.

## Getting a token
First, you would need to obtain a token to the origin trial.
1. Open Google Chrome and head over to the Chrome Origin Trials Portal.
2. Click Sign In in the top right corner and log in using any standard Google account.
3. Scroll through the list of Active Trials on the dashboard.
4. Locate the specific experimental browser API you need to test.
5. Click the Register button next to that feature.
6. Fill out the registration details. <br>
   a. Web Origin: Enter your full website URL, including the protocol (e.g., https://yourdomain.com or https://github.io). It must use HTTPS. <br>
   b. Subdomain Match (Optional): Check this box if you need the feature to work on varying subdomains (e.g., ://yourdomain.com). NOTE: If you are using a free domain like github.io or pages.dev, leave this box unchecked or Google will reject it. <br>
   c. Third-Party (Optional): Only check this if your script is being injected into other people's websites. For your own site, leave it blank.
7. Your unique Base64 string is generated immediately. Put it into your index.html.

## Hosting the mirror
After you have gotten your token, hosting a mirror shouldn't be too hard
1. Go to whatever host you are using.
2. Choose your fork of this repository.
3. Host it.
You should have a working fork after this. If something breaks, please make an issue on this repository.
